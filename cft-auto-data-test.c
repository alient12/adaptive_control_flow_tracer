/*
 * SPDX-License-Identifier: MIT
 *
 * Preloadable control-flow tracer (LD_PRELOAD)
 * - Robust program_base() for PIE/ASLR
 * - In-process patching (no PID maps needed)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <dlfcn.h>
#include <link.h>

#include <capstone/capstone.h>
#include <libpatch/patch.h>

#include <inttypes.h>
#include <time.h>
#include <stdatomic.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <errno.h>

#include "trace_shared.h"
#include <sched.h>    // sched_getcpu
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "trigger_check.h"

/* ------------------------- trace buffer ------------------------- */
typedef struct {
    trace_event_t    *events;   // points into shared events shm
    trace_meta_cpu_t *meta;     // points into shared meta for this CPU
    uint64_t          capacity; // TRACE_BUF_CAPACITY
} trace_cpu_buffer_t;

static trace_meta_global_t *trace_gmeta      = NULL;
static trace_meta_cpu_t    *trace_cmeta      = NULL;
static void                *trace_events_base = NULL;

static trace_cpu_buffer_t  *trace_cpu_buffers = NULL;
static int                  trace_n_cpus      = 0;

/* ------------------------- trigger & probes ------------------------- */
static TriggerDB trigger_db;

typedef struct {
    patch_t *patches;
    bool    *ready;
    bool    *enabled;
    size_t   count;
} Probe2Set;

typedef struct {
    uintptr_t target_addr;
    uintptr_t trigger_addr;
    char* target_name;
    uint64_t target_size;
    Probe2Set p2set;
    size_t index;
} ProbeID;

typedef struct {
    ProbeID *probe_addrs;
    size_t      n_probes;
} ProbeIDList;

static ProbeIDList g_probe_list;

/* ------------------------- probe time vars ------------------------- */
typedef struct {
    _Atomic uint64_t calls;
    _Atomic uint64_t total_cycles;
} ProbeTimeStats;

static ProbeTimeStats g_probe_time_stats = {0};
static __thread uint64_t probe_time_t0 = 0;

/* make &main safe to reference even if not exported */
extern int main(int, char **, char **) __attribute__((weak));

int probe2_build_from_function(const void *func_addr,
                               size_t max_bytes,
                               Probe2Set *set,
                               void (*handler)(struct patch_exec_context*, uint8_t),
                               void *user_data);
void probe2_enable_all(Probe2Set *set);
void probe2_disable_all(Probe2Set *set);
void probe2_free(Probe2Set *set);
void trace_buffers_init(void);
static inline void trace_record(uint64_t tsc, uint64_t value);
static inline trace_cpu_buffer_t *trace_get_cpu_buffer(void);

/* compatibility with earlier call sites */
void probe2_set_enable_all(Probe2Set *set);
void probe2_set_disable_all(Probe2Set *set);

#ifndef RTLD_DL_LINKMAP
#define RTLD_DL_LINKMAP 2
#endif
#ifndef HAVE_DLADDR1
# if defined(__GLIBC__)
#  define HAVE_DLADDR1 1
# else
#  define HAVE_DLADDR1 0
# endif
#endif

/* ------------------------- config & globals ------------------------- */

bool mode_probe1_enabled = true;
bool mode_probe2_enabled = true;
static const size_t    target_func_max_bytes = 4096;   // how many bytes to scan if failed to get function size

static uintptr_t program_base(void); // early fwd so we can use it above

static void probe1(struct patch_exec_context *ctx, uint8_t ret);
static void probe2(struct patch_exec_context *ctx, uint8_t ret);
static void install_probe1(void *func_addr);
static void print_libpatch_error(void);


typedef struct JumpSite {
    uintptr_t insn_addr;      // branch instruction address
    uintptr_t next_addr;      // fallthrough (insn_addr + size)
    uintptr_t imm_target;     // immediate target if present
    unsigned  is_conditional:1;
    unsigned  is_unconditional:1;
    unsigned  is_indirect:1;
    unsigned  is_call:1;
    unsigned  is_ret:1;
} JumpSite;

static void dump_jump_sites(const JumpSite *sites, size_t n, uintptr_t base)
{
    for (size_t i = 0; i < n; ++i) {
        const JumpSite *s = &sites[i];
        const char *kind  =
            s->is_ret           ? "RET"  :
            s->is_call          ? "CALL" :
            s->is_unconditional ? "JMP"  :
            s->is_conditional   ? "Jcc"  : "OTHER";

        printf("[jump] insn=0x%016" PRIxPTR
               " (rel +0x%016" PRIxPTR ")  next=0x%016" PRIxPTR
               "  kind=%s%s  imm_target=%s0x%016" PRIxPTR "\n",
               (uintptr_t)s->insn_addr,
               (uintptr_t)(s->insn_addr - base),
               (uintptr_t)s->next_addr,
               kind,
               s->is_indirect ? "(indirect)" : "",
               s->imm_target ? "" : "(none)",
               (uintptr_t)s->imm_target);
    }
}




/* Fallback stub so the .so loads even if the real builder isn't linked. */
/* ===== Capstone-based scanner: classify and list jumps inside a function ===== */
static inline bool classify_x86_branch(const cs_insn *insn, JumpSite *js) {
    const cs_detail *d = insn->detail;
    if (!d) return false;
    bool is_jump=false, is_call=false, is_ret=false;

    for (int g = 0; g < d->groups_count; ++g) {
        uint8_t grp = d->groups[g];
        if (grp == CS_GRP_JUMP) is_jump = true;
        else if (grp == CS_GRP_CALL) is_call = true;
        else if (grp == CS_GRP_RET)  is_ret  = true;
    }
    if (!(is_jump || is_call || is_ret)) return false;

    memset(js, 0, sizeof(*js));
    js->insn_addr = (uintptr_t)insn->address;
    js->next_addr = (uintptr_t)(insn->address + insn->size);

    if (is_ret) { js->is_ret = 1; return true; }

    if (is_call) {
        js->is_call = 1;
        for (int i = 0; i < d->x86.op_count; ++i) {
            const cs_x86_op *op = &d->x86.operands[i];
            if (op->type == X86_OP_IMM) { js->imm_target = (uintptr_t)op->imm; break; }
        }
        return true;
    }

    bool cond=false, uncond=false, indirect=false;
    if (insn->id == X86_INS_JMP) uncond = true; else cond = true; // other Jcc

    for (int i = 0; i < d->x86.op_count; ++i) {
        const const cs_x86_op *op = &d->x86.operands[i];
        if (op->type == X86_OP_MEM || op->type == X86_OP_REG) indirect = true;
        if (op->type == X86_OP_IMM) js->imm_target = (uintptr_t)op->imm;
    }
    js->is_conditional   = cond && !uncond;
    js->is_unconditional = uncond;
    js->is_indirect      = indirect && js->imm_target == 0;
    return true;
}

static int find_function_jumps(const void *func_addr,
                               size_t max_bytes,
                               JumpSite **out_sites,
                               size_t *out_count)
{
    if (!func_addr || !out_sites || !out_count) return -EINVAL;
    *out_sites = NULL; *out_count = 0;

    csh handle; cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    if (err != CS_ERR_OK) return -EFAULT;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    const uint8_t *code = (const uint8_t*)func_addr;
    uint64_t addr = (uint64_t)(uintptr_t)func_addr;

    cs_insn *insn = NULL;
    size_t n = cs_disasm(handle, code, max_bytes, addr, 0, &insn);
    if (n == 0) { cs_close(&handle); return -ENOEXEC; }

    JumpSite *sites = (JumpSite*)calloc(n, sizeof(JumpSite));
    if (!sites) { cs_free(insn, n); cs_close(&handle); return -ENOMEM; }

    size_t w = 0;
    for (size_t i = 0; i < n; ++i) {
        JumpSite js;
        if (classify_x86_branch(&insn[i], &js)) {
            if (!js.is_ret && !js.is_call) {         // <- keep only Jumps
                sites[w++] = js;
            }
            if (insn[i].id == X86_INS_RET || insn[i].id == X86_INS_RETF)
                break;                // stop scanning at function return
        }
    }

    cs_free(insn, n);
    cs_close(&handle);

    *out_sites = sites;
    *out_count = w;
    return 0;
}

/* ===== Build libpatch probe2 patches at each branch fallthrough ===== */
int probe2_build_from_function(const void *func_addr,
                               size_t max_bytes,
                               Probe2Set *set,
                               void (*handler)(struct patch_exec_context*, uint8_t),
                               void *user_data)
{
    if (!func_addr || !set || !handler) return -EINVAL;
    memset(set, 0, sizeof(*set));

    JumpSite *sites = NULL; size_t n = 0;
    int rc = find_function_jumps(func_addr, max_bytes, &sites, &n);
    if (rc) return rc;
    if (n == 0) { free(sites); return 0; }

    // Optional: print the discovered jump addresses
    dump_jump_sites(sites, n, program_base());

    set->patches = (patch_t*)calloc(n, sizeof(patch_t));
    set->ready   = (bool*)calloc(n, sizeof(bool));
    set->enabled = (bool*)calloc(n, sizeof(bool));
    if (!set->patches || !set->ready || !set->enabled) {
        free(sites); free(set->patches); free(set->ready); free(set->enabled);
        memset(set, 0, sizeof(*set));
        return -ENOMEM;
    }

    /* ***** libpatch strategy: forbid trap-based patches (no SIGTRAP punning) ***** */
    patch_attr   attr;
    patch_status st_attr;

    st_attr = patch_attr_init(&attr, sizeof(attr));
    if (st_attr != PATCH_OK) {
        print_libpatch_error();
        free(sites); free(set->patches); free(set->ready); free(set->enabled);
        memset(set, 0, sizeof(*set));
        return -EFAULT;
    }

    st_attr = patch_attr_set_trap_policy(&attr, PATCH_TRAP_POLICY_FORBID);
    if (st_attr != PATCH_OK) {
        print_libpatch_error();
        patch_attr_fini(&attr);
        free(sites); free(set->patches); free(set->ready); free(set->enabled);
        memset(set, 0, sizeof(*set));
        return -EFAULT;
    }

    st_attr = patch_attr_set_abi(&attr, PATCH_ABI_OS);
    if (st_attr != PATCH_OK) {
        print_libpatch_error();
        patch_attr_fini(&attr);
        free(sites); free(set->patches); free(set->ready); free(set->enabled);
        memset(set, 0, sizeof(*set));
        return -EFAULT;
    }
    /* ***** end libpatch strategy ***** */

    for (size_t i = 0; i < n; ++i) {
        const uintptr_t site = sites[i].next_addr; // patch after the branch
        struct patch_location location = {
            .type        = PATCH_LOCATION_RANGE,
            .direction   = PATCH_LOCATION_FORWARD,
            .algorithm   = PATCH_LOCATION_FIRST,
            .range.lower = site,
            .range.upper = 0,
        };
        struct patch_exec_model exec_model = {
            .type                    = PATCH_EXEC_MODEL_PROBE_AROUND,
            .probe.read_registers    = 0,
            .probe.write_registers   = 0,
            .probe.clobber_registers = PATCH_REGS_ALL,
            .probe.user_data         = user_data,
            .probe.procedure         = handler,
        };
        patch_status st = patch_make(&location, &exec_model, &attr,
                                     &set->patches[i], NULL);
        if (st == PATCH_OK) set->ready[i] = true; else print_libpatch_error();
    }

    /* ***** libpatch strategy: cleanup attributes ***** */
    patch_attr_fini(&attr);
    /* ***** end libpatch strategy ***** */

    free(sites);

    (void)patch_commit();
    set->count = n;
    return 0;
}

#define die(FMT, ARGS...)                 \
({                                        \
    fprintf(stderr, FMT "\n", ##ARGS);    \
    exit(EXIT_FAILURE);                    \
})

#define ensure_patch(FN, ARGS...)                      \
({                                                     \
    patch_status err = FN(ARGS);                        \
    if (PATCH_OK != err) {                              \
        fprintf(stderr, "error in " #FN "():\n");      \
        print_libpatch_error();                         \
        exit(EXIT_FAILURE);                             \
    }                                                   \
})

#define array_size(arr) (sizeof(arr) / (sizeof(arr[0])))


void probe2_enable_all(Probe2Set *set) {
    if (!set || !set->patches || !set->ready || !set->enabled) return;
    for (size_t i = 0; i < set->count; i++) {
        if (set->ready[i] && !set->enabled[i]) {
            ensure_patch(patch_enable, set->patches[i]);
            set->enabled[i] = true;
        }
    }
    (void)patch_commit();
}

void probe2_disable_all(Probe2Set *set) {
    if (!set || !set->patches || !set->ready || !set->enabled) return;
    for (size_t i = 0; i < set->count; i++) {
        if (set->enabled[i]) {
            ensure_patch(patch_disable, set->patches[i]);
            set->enabled[i] = false;
        }
    }
    (void)patch_commit();
}

/* ------------------------- timing helpers ------------------------- */

static inline uint64_t rdtsc(void) {
    unsigned lo, hi;
    __asm__ __volatile__("lfence\n rdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    return ((uint64_t)hi << 32) | lo;
}

static double cycles_per_ns = 0.0;

static void calibrate_tsc(void) {
    struct timespec t0, t1;
    uint64_t c0, c1;
    clock_gettime(CLOCK_MONOTONIC_RAW, &t0);
    c0 = rdtsc();
    struct timespec spin_end;
    clock_gettime(CLOCK_MONOTONIC_RAW, &spin_end);
    long target_ns = 50*1000*1000;
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
        long dt = (t1.tv_sec - spin_end.tv_sec)*1000000000L + (t1.tv_nsec - spin_end.tv_nsec);
        if (dt >= target_ns) break;
    }
    c1 = rdtsc();
    clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
    double ns = (t1.tv_sec - t0.tv_sec)*1e9 + (double)(t1.tv_nsec - t0.tv_nsec);
    cycles_per_ns = (double)(c1 - c0) / ns;
    if (cycles_per_ns <= 0) cycles_per_ns = 3.5; // fallback guess
}

/* Per-probe accounting */
static _Atomic uint64_t probe1_calls = 0, probe2_calls = 0;
static _Atomic uint64_t probe1_cycles = 0, probe2_cycles = 0;
static __thread uint64_t probe1_t0 = 0, probe2_t0 = 0;

/* ------------------------- disasm-lite helper ------------------------- */

uintptr_t x86_next_addr(const void *addr) {
    static csh handle = 0;

    // initialize Capstone once
    if (!handle) {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            fprintf(stderr, "[next_addr] failed to initialize Capstone\n");
            return 0;
        }
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
    }

    cs_insn *insn;
    size_t count;

    // disassemble 15 bytes from addr (max x86-64 instruction length)
    count = cs_disasm(handle, (const uint8_t *)addr, 15, (uintptr_t)addr, 1, &insn);
    if (count == 0) {
        fprintf(stderr, "[next_addr] disassembly failed at %p\n", addr);
        return 0;
    }

    uintptr_t next = insn[0].address + insn[0].size;
    cs_free(insn, count);
    return next;
}

uintptr_t x86_nth_next_addr(const void *addr, size_t n)
{
    const uint8_t *p = (const uint8_t*)addr;
    uintptr_t next = (uintptr_t)p;

    for (size_t i = 0; i < n; ++i) {
        uintptr_t tmp = x86_next_addr((const void*)next);
        if (!tmp || tmp <= next) {
            fprintf(stderr,
                    "[x86_nth_next_addr] decode stopped at step %zu (addr=%p)\n",
                    i, (void*)next);
            return 0;
        }
        next = tmp;
    }

    return next;
}

/* ------------------------- error reporting ------------------------- */

static int exit_value = 0;

static void print_libpatch_error(void) {
    patch_status status;
    struct patch_error err, *perr;
    status = patch_last_error(&err);
    if (PATCH_OK == status) return;
    for (perr=&err; perr; perr=perr->next) {
        fprintf(stderr, "#:code %d #:origin %s #:irritant %s #:message %s\n",
                perr->code, perr->origin, perr->irritant, perr->message);
    }
}

/* ------------------------- main executable base detection ------------------------- */

static uintptr_t g_main_base = 0;
static char g_exe_path[PATH_MAX] = {0};

static int phdr_cb(struct dl_phdr_info *info, size_t sz, void *data) {
    (void)sz;
    const char *exe = (const char*)data;
    if (!info->dlpi_name || info->dlpi_name[0] == '\0') {
        if (g_main_base == 0) g_main_base = (uintptr_t)info->dlpi_addr;
        return 0;
    }
    if (exe && exe[0] != '\0') {
        if (strcmp(info->dlpi_name, exe) == 0) { g_main_base = (uintptr_t)info->dlpi_addr; return 1; }
        const char *b1 = strrchr(info->dlpi_name, '/');
        const char *b2 = strrchr(exe, '/');
        if (b1 && b2 && strcmp(b1 + 1, b2 + 1) == 0) { if (g_main_base == 0) g_main_base = (uintptr_t)info->dlpi_addr; }
    }
    return 0;
}

static uintptr_t find_base_from_maps(const char *exe) {
    if (!exe || exe[0] == '\0') return 0;
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, exe)) {
            uintptr_t start = 0;
            if (sscanf(line, "%" PRIxPTR "-", &start) == 1) { fclose(f); return start; }
        }
    }
    fclose(f);
    return 0;
}

static void fill_exe_path(void) {
    if (g_exe_path[0] != '\0') return;
    ssize_t n = readlink("/proc/self/exe", g_exe_path, sizeof(g_exe_path) - 1);
    if (n > 0) g_exe_path[n] = '\0'; else g_exe_path[0] = '\0';
}

static uintptr_t program_base(void) {
    if (g_main_base) return g_main_base;

#if HAVE_DLADDR1
    if (&main) {
        Dl_info dinfo; struct link_map *lm = NULL;
        if (dladdr1((void*)(uintptr_t)&main, &dinfo, (void**)&lm, RTLD_DL_LINKMAP) != 0 && lm) {
            g_main_base = (uintptr_t)lm->l_addr; return g_main_base;
        }
    }
#else
    if (&main) {
        Dl_info dinfo; if (dladdr((void*)(uintptr_t)&main, &dinfo) != 0 && dinfo.dli_fbase) {
            g_main_base = (uintptr_t)dinfo.dli_fbase; return g_main_base;
        }
    }
#endif

    fill_exe_path();
    dl_iterate_phdr(phdr_cb, g_exe_path);
    if (g_main_base) return g_main_base;

    if (g_exe_path[0]) { g_main_base = find_base_from_maps(g_exe_path); if (g_main_base) return g_main_base; }
    return 0;
}

/* ------------------------- probe management ------------------------- */

static void probe2_configure_all(ProbeID *probe_addrs) {
    // Where to scan: program base + function entry offset
    uint64_t func_size = probe_addrs->target_size;
    uintptr_t func_addr = probe_addrs->target_addr;
    char *func_name = probe_addrs->target_name;
    Probe2Set *p2set = &probe_addrs->p2set;

    printf("[probe2-config] scanning function '%s' at %p (size=%" PRIu64 " bytes)\n",
           func_name, (void*)func_addr, func_size);
    int rc = probe2_build_from_function((void*)func_addr,
                                        func_size,
                                        p2set,
                                        &probe2,           // your existing handler
                                        &exit_value);      // your existing user_data
    if (rc) {
        fprintf(stderr, "[probe2-config] builder rc=%d\n", rc);
    } else {
        fprintf(stderr, "[probe2-config] built %zu probe sites\n", p2set->count);
    }
}

static void install_probe1(void *func_addr) {
    if (!func_addr) {
        fprintf(stderr, "[probe1] invalid func_addr\n");
        return;
    }

    printf("[probe1] Installing probe1 at %p\n", func_addr);

    const struct patch_option options[] = {
        { .type = PATCH_OPT_ENABLE_WXE, .enable_wxe = 0 },
    };

    struct patch_location location = {
        .type        = PATCH_LOCATION_RANGE,
        .direction   = PATCH_LOCATION_FORWARD,
        .algorithm   = PATCH_LOCATION_FIRST,
        .range.lower = (uintptr_t)func_addr,
        .range.upper = 0,
    };

    struct patch_exec_model exec_model = {
        .type                    = PATCH_EXEC_MODEL_PROBE_RETURN,
        .probe.read_registers    = 0,
        .probe.write_registers   = 0,
        .probe.clobber_registers = PATCH_REGS_ALL,
        .probe.user_data         = &exit_value,
        .probe.procedure         = &probe1,
    };

    patch_t patch;
    ensure_patch(patch_make, &location, &exec_model, NULL, &patch, NULL);
    ensure_patch(patch_enable, patch);
    (void)patch_commit();
}

/* ------------------------- probes ------------------------- */

static void probe1(struct patch_exec_context *ctx, uint8_t post) {
    if (!post) {
        /*************************************** probe 1 code **************************************/
        probe1_t0 = rdtsc();
        int x = (int)ctx->general_purpose_registers[PATCH_X86_64_RDI];
        uintptr_t pc = (uintptr_t)ctx->program_counter;

        // find probe index by pc
        size_t probe_index = 0;
        for (size_t i = 0; i < g_probe_list.n_probes; ++i) {
            if (pc >= g_probe_list.probe_addrs[i].target_addr &&
                pc <  g_probe_list.probe_addrs[i].target_addr + g_probe_list.probe_addrs[i].target_size) {
                probe_index = i;
                break;
            }
        }
        Probe2Set *p2set = &g_probe_list.probe_addrs[probe_index].p2set;

        uint64_t *raw;
        const FuncSig *sig = trigger_db.entries[probe_index].sig;
        extract_raw_args_sysv_x86_64(ctx, sig, raw);

        int result = eval_compiled_trigger(&trigger_db.entries[probe_index].compiled, sig, raw);

        //print raw args
        printf("[probe1-%zu]: raw args: ", probe_index);
        for (size_t i = 0; i < sig->n_args; ++i) {
            printf("%" PRIu64 " ", raw[i]);
        }
        printf("\n");
        printf("[probe1-%zu]: eval trigger result: %d\n", probe_index, result);
        
        // // in case non-pointer var used as pointer
        // int value = *(int*)raw[0];
        // printf("extracted value: %d\n", value);
        
        // result = 1; // for testing, always enable probe2
        if (mode_probe2_enabled) {
            if (result) probe2_enable_all(p2set); else probe2_disable_all(p2set);
        }

        uint64_t d = rdtsc() - probe1_t0;
        atomic_fetch_add_explicit(&probe1_cycles, d, memory_order_relaxed);
        atomic_fetch_add_explicit(&probe1_calls, 1, memory_order_relaxed);
        /************************************* probe_time code *************************************/
        probe_time_t0 = rdtsc();
    } else {
        /************************************* probe_time code *************************************/
        uint64_t d = rdtsc() - probe_time_t0;
        atomic_fetch_add_explicit(&g_probe_time_stats.total_cycles, d, memory_order_relaxed);
        atomic_fetch_add_explicit(&g_probe_time_stats.calls, 1, memory_order_relaxed);
        printf("[probe_time]: function took %llu cycles\n", (unsigned long long)d);
    }
}

static void probe2(struct patch_exec_context *ctx, uint8_t post) {
    unsigned long long *e = ctx->user_data;
    if (post) {
        uint64_t t1 = rdtsc();
        uint64_t d  = t1 - probe2_t0;
        atomic_fetch_add_explicit(&probe2_cycles, d, memory_order_relaxed);
        atomic_fetch_add_explicit(&probe2_calls, 1, memory_order_relaxed);
        // printf("probe2 at offset 0x%llx\n", (unsigned long long)(*e));

        uint64_t offset = *e;
        trace_record(t1, offset);
    } else {
        probe2_t0 = rdtsc();
        unsigned long long offset = (unsigned long long)ctx->program_counter - (unsigned long long)program_base();
        *e = (uint64_t)offset;
    }
}

/* ------------------------- summary ------------------------- */

/* report collected timing results */
void print_probe_time_summary(void) {
    if (g_probe_time_stats.calls == 0) {
        printf("[probe_time] No calls recorded.\n");
        return;
    }
    double avg_ns = (g_probe_time_stats.total_cycles / (double)g_probe_time_stats.calls) / cycles_per_ns;
    printf("[probe_time] calls=%" PRIu64 ", avg time=%.2f ns (%.0f cycles)\n",
           g_probe_time_stats.calls, avg_ns,
           (double)g_probe_time_stats.total_cycles / (double)g_probe_time_stats.calls);
}

__attribute__((noinline))
void print_test_summary(void) {
    double p1_avg_ns = (probe1_calls ? (probe1_cycles / (double)probe1_calls) / cycles_per_ns : 0.0);
    double p2_avg_ns = (probe2_calls ? (probe2_cycles / (double)probe2_calls) / cycles_per_ns : 0.0);
    printf("[overhead] probe1: calls=%" PRIu64 " avg≈%.2f ns\n", (uint64_t)probe1_calls, p1_avg_ns);
    printf("[overhead] probe2: calls=%" PRIu64 " avg≈%.2f ns\n", (uint64_t)probe2_calls, p2_avg_ns);

    FILE* f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof line, f)) {
            if (!strncmp(line, "VmPeak:", 7) || !strncmp(line, "VmHWM:", 6)) fputs(line, stdout);
        }
        fclose(f);
    }
}

/* ------------------------- trace buffer management ------------------------- */

void trace_buffers_init(void)
{
    if (trace_cpu_buffers) {
        // already initialised
        return;
    }

    long n = sysconf(_SC_NPROCESSORS_CONF);
    if (n <= 0) n = 1;
    if (n > TRACE_MAX_CPUS) n = TRACE_MAX_CPUS;
    trace_n_cpus = (int)n;

    /* ---------- 1) META shared memory (global + per-CPU meta) ---------- */

    size_t meta_size = sizeof(trace_meta_global_t)
                     + (size_t)trace_n_cpus * sizeof(trace_meta_cpu_t);

    int meta_fd = shm_open(TRACE_SHM_META_NAME, O_CREAT | O_RDWR, 0600);
    if (meta_fd < 0) {
        perror("trace: shm_open(meta)");
        return;
    }
    if (ftruncate(meta_fd, (off_t)meta_size) < 0) {
        perror("trace: ftruncate(meta)");
        close(meta_fd);
        return;
    }

    void *meta_base = mmap(NULL, meta_size,
                           PROT_READ | PROT_WRITE,
                           MAP_SHARED, meta_fd, 0);
    close(meta_fd);  // mapping stays valid

    if (meta_base == MAP_FAILED) {
        perror("trace: mmap(meta)");
        return;
    }

    trace_gmeta = (trace_meta_global_t *)meta_base;
    trace_cmeta = (trace_meta_cpu_t *)((uint8_t *)meta_base + sizeof(trace_meta_global_t));

    // Fill global meta (what the daemon reads)
    trace_gmeta->n_cpus      = (uint32_t)trace_n_cpus;
    trace_gmeta->capacity    = TRACE_BUF_CAPACITY;
    trace_gmeta->record_size = sizeof(trace_event_t);
    trace_gmeta->_pad        = 0;

    // Initialise per-CPU meta
    for (int i = 0; i < trace_n_cpus; ++i) {
        atomic_store_explicit(&trace_cmeta[i].head, 0, memory_order_relaxed);
        atomic_store_explicit(&trace_cmeta[i].dropped, 0, memory_order_relaxed);
    }

    /* ---------- 2) EVENTS shared memory (per-CPU rings) ---------- */

    size_t per_cpu_bytes = TRACE_BUF_CAPACITY * sizeof(trace_event_t);
    size_t total_bytes   = (size_t)trace_n_cpus * per_cpu_bytes;

    int events_fd = shm_open(TRACE_SHM_EVENTS_NAME, O_CREAT | O_RDWR, 0600);
    if (events_fd < 0) {
        perror("trace: shm_open(events)");
        // leave meta mapped so daemon can see that tracing is "there" but empty
        return;
    }
    if (ftruncate(events_fd, (off_t)total_bytes) < 0) {
        perror("trace: ftruncate(events)");
        close(events_fd);
        return;
    }

    trace_events_base = mmap(NULL, total_bytes,
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED, events_fd, 0);
    close(events_fd);

    if (trace_events_base == MAP_FAILED) {
        perror("trace: mmap(events)");
        return;
    }

    /* ---------- 3) Local helper array mapping CPUs to their slices ---------- */

    trace_cpu_buffers = calloc((size_t)trace_n_cpus, sizeof(trace_cpu_buffer_t));
    if (!trace_cpu_buffers) {
        perror("trace: calloc(trace_cpu_buffers)");
        return;
    }

    uint8_t *p = (uint8_t *)trace_events_base;
    for (int i = 0; i < trace_n_cpus; ++i) {
        trace_cpu_buffers[i].capacity = TRACE_BUF_CAPACITY;
        trace_cpu_buffers[i].events   = (trace_event_t *)(p + (size_t)i * per_cpu_bytes);
        trace_cpu_buffers[i].meta     = &trace_cmeta[i];
    }
}


static inline trace_cpu_buffer_t *trace_get_cpu_buffer(void)
{
    if (!trace_cpu_buffers || trace_n_cpus <= 0) return NULL;

    int cpu = sched_getcpu();
    if (cpu < 0 || cpu >= trace_n_cpus) {
        return NULL;
    }
    return &trace_cpu_buffers[cpu];
}

static inline void trace_record(uint64_t tsc, uint64_t value)
{
    // choose CPU somehow (e.g. sched_getcpu());
    int cpu = sched_getcpu();
    if (cpu < 0 || cpu >= trace_n_cpus) return;

    trace_cpu_buffer_t *buf = &trace_cpu_buffers[cpu];
    if (!buf->events || !buf->meta || buf->capacity == 0) return;

    trace_meta_cpu_t *m = buf->meta;

    uint64_t idx = atomic_fetch_add_explicit(&m->head, 1, memory_order_relaxed);
    uint64_t slot = idx & (buf->capacity - 1);

    trace_event_t *ev = &buf->events[slot];
    ev->tsc   = tsc;
    ev->value = value;
}


/* ------------------------- constructor ------------------------- */

__attribute__((constructor))
static void preload_init(void) {
    puts("libB (preloaded) initialising...");

    calibrate_tsc();
    const struct patch_option options[] = {
        { .type = PATCH_OPT_ENABLE_WXE, .enable_wxe = 0 },
    };
    ensure_patch(patch_init, options, array_size(options));

    triggerdb_setup(&trigger_db, "config.yaml");

    for (size_t i = 0; i < trigger_db.n_entries; ++i) {
        if (trigger_db.entries[i].func_size > 0) {
            uintptr_t target_lowpc    = trigger_db.entries[i].func_lowpc;
            uintptr_t trigger_lowpc = trigger_db.entries[i].trigger_func_lowpc;
            char *target_name = trigger_db.entries[i].func_name;
            uint64_t target_size = trigger_db.entries[i].func_size > 0 ? trigger_db.entries[i].func_size : target_func_max_bytes;

            // check if name already in the list
            for (size_t j = 0; j < g_probe_list.n_probes; ++j) {
                if (strcmp(g_probe_list.probe_addrs[j].target_name, target_name) == 0) {
                    // already exists
                    target_lowpc = 0;
                    trigger_lowpc = 0;
                    break;
                }
            }
            if (target_lowpc == 0 || trigger_lowpc == 0) continue;

            g_probe_list.probe_addrs = (ProbeID*)realloc(g_probe_list.probe_addrs,
                                                             (g_probe_list.n_probes + 1) * sizeof(ProbeID));
            if (!g_probe_list.probe_addrs) {
                fprintf(stderr, "[probe2-config] failed to realloc probe addrs\n");
                return;
            }
            
            g_probe_list.probe_addrs[g_probe_list.n_probes].target_addr  = program_base() + target_lowpc;
            g_probe_list.probe_addrs[g_probe_list.n_probes].trigger_addr = program_base() + trigger_lowpc;
            g_probe_list.probe_addrs[g_probe_list.n_probes].target_name = target_name;
            g_probe_list.probe_addrs[g_probe_list.n_probes].target_size = target_size;
            g_probe_list.probe_addrs[g_probe_list.n_probes].p2set = (Probe2Set){0};
            g_probe_list.probe_addrs[g_probe_list.n_probes].index = i;
            g_probe_list.n_probes++;
        }
    }

    if (mode_probe1_enabled) for (size_t i = 0; i < g_probe_list.n_probes; ++i) {
        install_probe1((void*)g_probe_list.probe_addrs[i].trigger_addr);
    }
    if (mode_probe2_enabled) for (size_t i = 0; i < g_probe_list.n_probes; ++i) {
        probe2_configure_all(&g_probe_list.probe_addrs[i]); // enabled on demand by probe1
    }

    // uint64_t trigger_func_lowpc = trigger_db.entries[0].trigger_func_lowpc;
    // uintptr_t trigger_func_addr = program_base() + trigger_func_lowpc;
    

    // if (mode_probe1_enabled) install_probe1((void*)trigger_func_addr);
    // if (mode_probe2_enabled) { probe2_configure_all(); /* enabled on demand by probe1 */ }

    uintptr_t addr = program_base();
    printf("libB: main executable base address: 0x%" PRIxPTR "\n", addr);
}

__attribute__((constructor))
static void trace_constructor(void)
{
    trace_buffers_init();
}

/* ------------------------- destructor ------------------------- */

__attribute__((destructor))
static void preload_fini(void) {
    puts("libB (preloaded) shutting down...");

    (void) patch_fini();

	print_probe_time_summary();
    print_test_summary();

    puts("libB cleanup complete.");
}


/* ------------------------- (optional) original cross-proc helper kept for reference ------------------------- */
/* Not used in preload mode, but kept here for completeness */
uintptr_t base_address_for_pid(pid_t pid) {
    char path[PATH_MAX];
    char line[256];
    FILE *maps;
    uintptr_t base_addr = 0;
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    maps = fopen(path, "r");
    if (!maps) { perror("Failed to open /proc/[pid]/maps"); return 0; }
    while (fgets(line, sizeof(line), maps)) {
        uintptr_t start, end; char perms[5], offset[9], device[6], inode[9];
        if (sscanf(line, "%lx-%lx %4s %8s %5s %8s", &start, &end, perms, offset, device, inode) == 6) {
            if (strstr(perms, "r-x")) { base_addr = start; break; }
        }
    }
    fclose(maps);
    return base_addr;
}

/* ------------------------- build hints ------------------------- */
/*
Compile:
  gcc -shared -fPIC cft-auto-data-test.c trigger_check.c trigger_compiler.c trace_config.c -o cft-auto-data-test.so -I. -L. -ldwscan -Wl,-rpath,'$ORIGIN' -lyaml -ldl -lcapstone -lpatch
Run:
  LD_PRELOAD=$PWD/cft-auto-data-test.so ~/Codes/cpu2017/benchspec/CPU/505.mcf_r/run/run_base_refrate_ali-test1-m64.0000/mcf_r_base.ali-test1-m64 ~/Codes/cpu2017/benchspec/CPU/505.mcf_r/run/run_base_refrate_ali-test1-m64.0000/inp.in
  LD_PRELOAD=$PWD/cft-auto-data-test.so ~/Codes/cpu2017/benchspec/CPU/505.mcf_r/run/run_base_refrate_ali-test1-m64.0000/mcf_r_base.ali-test1-m64 ~/Codes/cpu2017/benchspec/CPU/505.mcf_r/data/test/input/inp.in
*/
