#define _GNU_SOURCE
#include "trigger_check.h"

#include <signal.h>
#include <setjmp.h>
#include <stdatomic.h>
#include <unistd.h>

#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>

static int safe_read_bytes(const void *addr, void *dst, size_t n)
{
    struct iovec local  = { .iov_base = dst,        .iov_len = n };
    struct iovec remote = { .iov_base = (void*)addr, .iov_len = n };

    ssize_t r = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    if (r < 0) return -errno;
    if ((size_t)r != n) return -EIO;
    return 0;
}

static int safe_read_ptr(const void *addr, void **out)
{
    return safe_read_bytes(addr, out, sizeof(void*));
}

static _Thread_local sigjmp_buf g_eval_jmp;
static _Thread_local int g_eval_jmp_active = 0;

static struct sigaction g_old_segv;
static atomic_int g_segv_installed = 0;

static void tc_segv_handler(int sig, siginfo_t *info, void *ucontext)
{
    (void)info; (void)ucontext;
    if (g_eval_jmp_active) {
        g_eval_jmp_active = 0;
        siglongjmp(g_eval_jmp, 1);
    }

    /* Not ours: chain */
    if (g_old_segv.sa_sigaction) {
        g_old_segv.sa_sigaction(sig, info, ucontext);
        return;
    }
    _exit(128 + sig);
}

static void tc_install_segv_once(void)
{
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_segv_installed, &expected, 1)) return;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = tc_segv_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    (void)sigaction(SIGSEGV, NULL, &g_old_segv);
    (void)sigaction(SIGSEGV, &sa, NULL);
}

/* ---- helpers (same style as your code) ---- */

static const VarType *vt_unwrap_local(const VarType *v) {
    while (v && (v->kind == VT_TYPEDEF || v->kind == VT_QUALIFIER)) v = v->under;
    return v;
}

static int vartype_is_float_or_double(const VarType *t) {
    t = vt_unwrap_local(t);
    if (!t) return 0;
    if (t->kind == VT_BASE && t->name) {
        return (strcmp(t->name, "float") == 0 || strcmp(t->name, "double") == 0);
    }
    return 0;
}

static int vartype_is_float(const VarType *t) {
    t = vt_unwrap_local(t);
    return (t && t->kind == VT_BASE && t->name && strcmp(t->name, "float") == 0);
}

static int vartype_is_double(const VarType *t) {
    t = vt_unwrap_local(t);
    return (t && t->kind == VT_BASE && t->name && strcmp(t->name, "double") == 0);
}

/*
  SysV x86-64 ABI:
    - Integer class args: RDI, RSI, RDX, RCX, R8, R9 then stack (8-byte slots)
    - FP args (float/double): XMM0..XMM7 then stack (8-byte slots)
  We do "best effort" classification based on DWARF type:
    - float/double => FP class
    - everything else => integer class (incl. pointers, struct pointers)
*/
int extract_raw_args_sysv_x86_64(const struct patch_exec_context *ctx,
                                 const FuncSig *f,
                                 uint64_t *out_raw_args)
{
    if (!ctx || !f || !out_raw_args) return -1;

    /* integer arg registers */
    static const int kIntRegs[6] = {
        PATCH_X86_64_RDI,
        PATCH_X86_64_RSI,
        PATCH_X86_64_RDX,
        PATCH_X86_64_RCX,
        PATCH_X86_64_R8,
        PATCH_X86_64_R9,
    };

    size_t int_i = 0;
    size_t fp_i  = 0;

    /* Stack args start at RSP+8 (skip return address) for a probe at function entry. */
    const uint8_t *sp = (const uint8_t*)(uintptr_t)ctx->stack_pointer;  /* :contentReference[oaicite:3]{index=3} */
    const uint8_t *stackp = sp ? (sp + 8) : NULL;
    size_t stack_slots_used = 0;

    if (!ctx->stack_pointer) return -10;
    uintptr_t spv = (uintptr_t)ctx->stack_pointer;
    /* alignment sanity: stack should be 8- or 16-byte aligned */
    if ((spv & 0x7) != 0) return -11;

    /* Try to access SSE state for XMM regs (if libpatch saved it). */
    struct patch_x86_64_legacy *sse = NULL;
    if (ctx->extended_states) {
        int rc = patch_x86_sse_state(ctx->extended_states, &sse);
        if (rc != PATCH_OK) sse = NULL;
        if (rc != PATCH_OK) printf("[warning] patch_x86_sse_state failed: %d\n", rc);
    }

    for (size_t a = 0; a < f->n_args; a++) {
        const VarType *t = f->args[a];
        t = vt_unwrap_local(t);

        int is_fp = vartype_is_float_or_double(t);

        if (is_fp) {
            /* Prefer XMM0..XMM7 */
            // if (sse && fp_i < 8) {
            //     /* In the legacy fxsave area, XMM regs are 128-bit; we read the low lane. */
            //     const uint64_t *xmm_base = &sse->xmm0[0];   /* contiguous: xmm0..xmm15 */
            //     const uint64_t lo64 = xmm_base[fp_i * 2 + 0];

            //     if (vartype_is_float(t)) {
            //         /* float is low 32 bits of XMM */
            //         uint32_t lo32 = (uint32_t)(lo64 & 0xffffffffu);
            //         out_raw_args[a] = (uint64_t)lo32;
            //     } else {
            //         /* double is low 64 bits of XMM */
            //         out_raw_args[a] = lo64;
            //     }
            //     fp_i++;
            //     continue;
            // }

            /* Spill to stack if no SSE saved or XMM regs exhausted */
            if (!stackp) return -2;
            uint64_t slot = 0;
            // memcpy(&slot, stackp + stack_slots_used * 8, 8);
            if (safe_read_bytes(stackp + stack_slots_used * 8, &slot, 8) != 0)
            {
                printf("[error] safe_read_bytes failed for FP arg spill at %p\n", stackp + stack_slots_used * 8);
                return -4;
            }
            out_raw_args[a] = slot;
            stack_slots_used++;
            continue;
        }

        /* Integer/pointer class */
        if (int_i < 6) {
            uint64_t regv = 0;
            if (safe_read_bytes(&ctx->general_purpose_registers[kIntRegs[int_i]], &regv, sizeof(regv)) != 0) {
                printf("[error] safe_read_bytes failed for GPR reg index %d\n", kIntRegs[int_i]);
                return -5;
            }
            out_raw_args[a] = regv;
            int_i++;
            continue;
        }

        /* Spill to stack */
        if (!stackp) return -3;
        uint64_t slot = 0;
        // memcpy(&slot, stackp + stack_slots_used * 8, 8);
        if (safe_read_bytes(stackp + stack_slots_used * 8, &slot, 8) != 0)
        {
            printf("[error] safe_read_bytes failed for integer arg spill at %p\n", stackp + stack_slots_used * 8);
            return -4;
        }
        out_raw_args[a] = slot;
        stack_slots_used++;
    }

    return 0;
}


static char *tc_strdup_local(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *p = (char*)malloc(n + 1);
    if (!p) return NULL;
    // memcpy(p, s, n + 1);
    if (safe_read_bytes(s, p, n + 1) != 0)
    {
        printf("[error] safe_read_bytes failed for strdup at %p\n", s);
        free(p);
        return NULL;
    }
    return p;
}

static void triggerdb_free(TriggerDB *db)
{
    if (!db) return;

    if (db->entries) {
        for (size_t i = 0; i < db->n_entries; i++) {
            TriggerEntry *e = &db->entries[i];
            if (e->compiled_ok) compiled_trigger_free(&e->compiled);
            free(e->func_name);
            free(e->trigger_func_name);
            free(e->trigger_expr);
        }
        free(db->entries);
    }

    /* cfg_free frees heap allocations inside cfg */
    cfg_free(&db->cfg);

    /* model owns FuncSig/VarType graphs */
    dwarf_model_free(db->model);

    memset(db, 0, sizeof(*db));
}

/* Build a flattened list of all triggers across all targets.
   db->model + db->cfg stay alive so db->entries[i].sig remains valid. */
int triggerdb_setup(TriggerDB *db, const char *cfg_path)
{
    if (!db) return -1;
    memset(db, 0, sizeof(*db));

    db->model = dwarf_scan_collect_model();
    if (!db->model) {
        printf("[error] failed to build DWARF model. make sure the target is compiled with debug info\n");
        return -2;
    }

    if (!cfg_path) cfg_path = "config.yaml";
    if (load_trace_config(cfg_path, &db->cfg) != 0) {
        printf("failed to load %s\n", cfg_path);
        dwarf_model_free(db->model);
        db->model = NULL;
        return -3;
    }

    /* Count total triggers */
    size_t total = 0;
    for (size_t i = 0; i < db->cfg.n_targets; i++) {
        total += db->cfg.targets[i].triggers.n;
    }

    db->n_entries = total;
    db->entries = (TriggerEntry*)calloc(total ? total : 1, sizeof(TriggerEntry));
    if (!db->entries && total) {
        triggerdb_free(db);
        return -4;
    }

    dwarf_build_function_offset_table();
    dwarf_update_function_offset_table_from_elf(1);

    /* Fill entries */
    size_t idx = 0;
    for (size_t ti = 0; ti < db->cfg.n_targets; ti++) {
        const TargetCfg *t = &db->cfg.targets[ti];

        uint64_t func_off = 0, func_size = 0;
        uint64_t trig_off = 0, trig_size = 0;
        
        (void)dwarf_find_function_lowpc(t->func, &func_off, &func_size);
        (void)dwarf_find_function_lowpc(t->trigger_func, &trig_off, &trig_size);

        printf("[triggerdb-setup] Target %zu: Func=%s, Offset=0x%lx, Size=0x%lx, Recursive=%d, TriggerFunc=%s, TriggerOffset=0x%lx, TriggerSize=0x%lx, Triggers=[",
               ti, t->func, func_off, func_size, t->recursive, t->trigger_func, trig_off, trig_size);
        for (size_t j = 0; j < t->triggers.n; j++) {
            printf("%s\"%s\"", (j > 0) ? ", " : "", t->triggers.items[j]);
        }
        printf("]\n");

        const FuncSig *sig = find_funcsig_by_name(db->model, t->trigger_func);
        if (!sig) {
            printf("[Error] no FuncSig found for trigger function '%s'\n", t->trigger_func);
        }

        for (size_t k = 0; k < t->triggers.n; k++) {
            TriggerEntry *e = &db->entries[idx];
            memset(e, 0, sizeof(*e));

            e->index      = idx;
            e->target_i   = ti;
            e->trigger_i  = k;

            e->func_name  = tc_strdup_local(t->func);
            e->func_lowpc = func_off;
            e->func_size  = func_size;

            e->trigger_func_name  = tc_strdup_local(t->trigger_func);
            e->trigger_func_lowpc = trig_off;
            e->trigger_func_size  = trig_size;

            e->recursive  = t->recursive;

            e->trigger_expr = tc_strdup_local(t->triggers.items[k]);
            e->sig = (const FuncSig *)sig;

            if (sig) {
                if (compile_trigger(&e->compiled, t->triggers.items[k], sig) == 0) {
                    e->compiled_ok = 1;
                } else {
                    e->compiled_ok = 0;
                    printf("[Error] failed to compile trigger[%zu] for %s: %s\n",
                           k, t->trigger_func, t->triggers.items[k]);
                }
            }

            idx++;
        }
    }

    return 0;
}

static inline const TriggerEntry *triggerdb_get(const TriggerDB *db, size_t index)
{
    if (!db || !db->entries || index >= db->n_entries) return NULL;
    return &db->entries[index];
}

void demo()
{
    DwarfModel *model = dwarf_scan_collect_model();
    if (!model) {
        printf("[error] failed to build DWARF model. make sure the target is compiled with debug info\n");
        return;
    }

    TraceConditionCfg cfg;
    const char *cfg_path = getenv("TRACE_CONFIG");
    if (!cfg_path) cfg_path = "config.yaml";
    if (load_trace_config(cfg_path, &cfg) != 0) {
        printf("failed to load %s\n", cfg_path);
        dwarf_model_free(model);
        return;
    }

    // for each target in cfg, print its function name and triggers
    for (size_t i = 0; i < cfg.n_targets; i++) {
        const TargetCfg *t = &cfg.targets[i];

        dwarf_build_function_offset_table();
        dwarf_update_function_offset_table_from_elf(/*include_plt=*/1);
        
        uint64_t offset, trigger_offset;
        uint64_t size, trigger_size;
        dwarf_find_function_lowpc(t->func, &offset, &size);
        dwarf_find_function_lowpc(t->trigger_func, &trigger_offset, &trigger_size);
        
        printf("Target %zu: Func=%s, Offset=0x%lx, Size=0x%lx, Recursive=%d, TriggerFunc=%s, TriggerOffset=0x%lx, TriggerSize=0x%lx, Triggers=[", i, t->func, offset, size, t->recursive, t->trigger_func, trigger_offset, trigger_size);
        for (size_t j = 0; j < t->triggers.n; j++) {
            printf("%s\"%s\"", (j > 0) ? ", " : "", t->triggers.items[j]);
        }
        printf("]\n");

        const FuncSig *f = find_funcsig_by_name(model, t->trigger_func);
        printf("found function %s with %zu args\n", f->name, f->n_args);

        printf("[demo] loaded %zu trigger(s) for %s\n", t->triggers.n, t->trigger_func);

        CompiledTrigger *compiled = NULL;
        if (t->triggers.n) {
            compiled = (CompiledTrigger*)calloc(t->triggers.n, sizeof(CompiledTrigger));
            for (size_t k = 0; k < t->triggers.n; k++) {
                if (compile_trigger(&compiled[k], t->triggers.items[k], f) != 0) {
                    printf("failed to compile trigger[%zu]: %s\n", k, t->triggers.items[k]);
                }
            }
        }
        
        if (compiled) {
            for (size_t k = 0; k < t->triggers.n; k++) compiled_trigger_free(&compiled[k]);
            free(compiled);
        }
    }


    cfg_free(&cfg);
    dwarf_model_free(model);
}

// __attribute__((constructor))
// static void on_load(void)
// {
//     demo();
// }

// __attribute__((destructor))
// static void on_unload(void)
// {

// }

// gcc -shared -fPIC trigger_check.c trigger_compiler.c trace_config.c -o trigger_check.so -I. -L. -ldwscan -Wl,-rpath,'$ORIGIN' -lyaml
// LD_PRELOAD=./trigger_check.so ~/Codes/cpu2017/benchspec/CPU/505.mcf_r/run/run_base_refrate_ali-test1-m64.0000/mcf_r_base.ali-test1-m64