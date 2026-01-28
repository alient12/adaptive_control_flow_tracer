/*
  Consumer-side demo: DWARF-driven arg metadata + YAML-driven trigger evaluation
  -------------------------------------------------------------------------
  - This code is intended to be built into an LD_PRELOAD .so (consumer).
  - It uses libdwscan for: dwarf_scan_collect_model(), find_funcsig_by_name(), VarType.
  - It uses libyaml for: loading config.yaml
  - It evaluates trigger expressions containing:
      * variables: argN or argN.member.submember
      * comparisons: == != < <= > >= (single '=' is treated as '==')
      * boolean ops: && ||
      * literals: int (10), hex (0x10), float (3.14), string ("abc")
  - For struct member access, it uses resolve_member_path() (no C struct casts).

  NOTE:
    read_u64() is STILL a stub that returns pseudo-random values so you can
    verify the pipeline end-to-end before doing real memory reads.
*/

#define _GNU_SOURCE

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>

#include "trigger_compiler.h"

/* ============================== Timing helpers =============================== */
#include <time.h>

static inline void timer_start(struct timespec *t)
{
    clock_gettime(CLOCK_MONOTONIC, t);
}

static inline void timer_end(const struct timespec *t0, const char *label, size_t iterations)
{
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double elapsed =
        (t1.tv_sec  - t0->tv_sec) +
        (t1.tv_nsec - t0->tv_nsec) * 1e-9;

    printf("[time] %s: %.6f sec\n", label ? label : "elapsed", elapsed);
    if (iterations > 0) {
        printf("        %.3f nsec per iteration\n", (elapsed * 1e9) / (double)iterations);
    }
}

/* ======================= Core: member path resolution ======================= */

static const VarType *vt_unwrap(const VarType *v)
{
    while (v && (v->kind == VT_TYPEDEF || v->kind == VT_QUALIFIER))
        v = v->under;
    return v;
}

static const StructMember *vt_find_member(const VarType *s, const char *name)
{
    if (!s || !name) return NULL;
    if (s->kind != VT_STRUCT && s->kind != VT_UNION) return NULL;

    for (size_t i = 0; i < s->n_members; i++) {
        if (s->members[i].name && strcmp(s->members[i].name, name) == 0)
            return &s->members[i];
    }
    return NULL;
}

static const char *path_next(const char *p, char *out, size_t cap)
{
    size_t i = 0;
    while (*p && *p != '.') {
        if (i + 1 < cap) out[i++] = *p;
        p++;
    }
    out[i] = '\0';
    if (*p == '.') p++;
    return p;
}

/*
   Resolve a.b.c starting from (base_addr, base_type)
   Follows pointers automatically.

   base_addr is treated as:
     - the address of the object if base_type is struct/union
     - the address of a pointer if base_type is pointer

   In your trigger language, argN is normally a register value, so for
   struct member access we treat argN as a pointer-to-struct address.
*/
int resolve_member_path(void *base_addr,
                        const VarType *base_type,
                        const char *path,
                        void **out_addr,
                        const VarType **out_type)
{
    if (!base_addr || !base_type || !path || !out_addr || !out_type) return -1;

    const VarType *t = base_type;
    void *addr = base_addr;
    char tok[128];

    const char *p = path;
    while (*p) {
        p = path_next(p, tok, sizeof(tok));
        if (!tok[0]) return -2;

        t = vt_unwrap(t);

        if (t && t->kind == VT_POINTER) {
            /* Follow pointer value stored at 'addr' */
            if (!addr) return -3;
            t = t->pointee;
        }

        t = vt_unwrap(t);
        if (!t || (t->kind != VT_STRUCT && t->kind != VT_UNION)) return -4;

        const StructMember *m = vt_find_member(t, tok);
        if (!m || m->offset < 0) return -5;

        addr = (uint8_t*)addr + (size_t)m->offset;
        t = m->type;
    }

    *out_addr = addr;
    *out_type = t;
    return 0;
}

/* ======================= Trigger expression evaluation (compiled once) ======================= */

/*
  Hot path goal:
    - Parse each trigger string ONCE (after loading YAML)
    - Precompile variable references (argN.member.member) into offset/deref steps
    - Evaluate compiled AST repeatedly with new raw_args (no lex/parse at runtime)

  This is already a big win vs parsing every call. Later we can switch to bytecode.
*/

static Value V_int(int64_t x)      { Value r={VK_INT};   r.v.i=x; return r; }
static Value V_float(double x)    { Value r={VK_FLOAT}; r.v.f=x; return r; }
static Value V_bool(int x)        { Value r={VK_BOOL};  r.v.b=!!x; return r; }
static Value V_str(const char *s) { Value r={VK_STRING};r.v.s=s?s:""; return r; }
static Value V_invalid(void)      { Value r={VK_INVALID}; return r; }

static int value_truthy(Value v)
{
    if (v.kind == VK_BOOL) return v.v.b;
    if (v.kind == VK_INT) return v.v.i != 0;
    if (v.kind == VK_FLOAT) return v.v.f != 0.0;
    if (v.kind == VK_STRING) return v.v.s && v.v.s[0] != 0;
    return 0;
}

static int is_floatish_name(const char *n)
{
    if (!n) return 0;
    // return (strcmp(n, "float") == 0 || strcmp(n, "double") == 0);
    return (strcmp(n, "float") == 0);
}

static int is_doubleish_name(const char *n)
{
    if (!n) return 0;
    return (strcmp(n, "double") == 0);
}

static int is_cstring_ptr(const VarType *t)
{
    t = vt_unwrap(t);
    if (!t || t->kind != VT_POINTER) return 0;
    const VarType *p = vt_unwrap(t->pointee);
    if (!p || p->kind != VT_BASE) return 0;
    if (!p->name) return 0;
    return (strcmp(p->name, "char") == 0 || strcmp(p->name, "signed char") == 0 || strcmp(p->name, "unsigned char") == 0);
}

/* Parse arg index from "arg{n}" */
static int parse_arg_index(const char *ident)
{
    if (!ident) return -1;
    if (strncmp(ident, "arg", 3) != 0) return -1;
    const char *p = ident + 3;
    if (!isdigit((unsigned char)*p)) return -1;
    long v = strtol(p, NULL, 10);
    if (v < 0) return -1;
    return (int)v;
}

/* ======================= TEMP read (stub) ======================= */

/* Read raw 64-bit scalar safely (no casting)
   TEMP: returns pseudo-random so you can validate the pipeline.
*/
int read_u64(void *addr, uint64_t *out)
{
    (void)addr;
    if (!out) return -1;
    static uint64_t seed = 0x12345678abcdefULL;
    seed ^= seed << 7;
    seed ^= seed >> 9;
    seed ^= seed << 8;
    *out = seed;
    return 0;
}


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

static int read_scalar_value(void *addr, const VarType *t, ValueKind hint, Value *out)
{
    if (!out) return -1;
    *out = V_invalid();

    t = vt_unwrap(t);
    if (!t || !addr) return -2;

    /* Strings are handled elsewhere (cstring ptr), this is for scalars in memory */
    if (hint == VK_FLOAT) {
        /* float/double by name (best effort) */
        if (t->kind == VT_BASE && t->name && strcmp(t->name, "float") == 0) {
            float fv = 0.0f;
            // memcpy(&fv, addr, sizeof(fv));
            if (safe_read_bytes(addr, &fv, sizeof(fv)) != 0)
            {
                printf("[error] safe_read_bytes failed for float read at %p\n", addr);
                return 1;
            }
            *out = V_float((double)fv);
            return 0;
        }
        if (t->kind == VT_BASE && t->name && strcmp(t->name, "double") == 0) {
            double dv = 0.0;
            // memcpy(&dv, addr, sizeof(dv));
            if (safe_read_bytes(addr, &dv, sizeof(dv)) != 0)
            {
                printf("[error] safe_read_bytes failed for double read at %p\n", addr);
                return 1;
            }
            *out = V_float(dv);
            return 0;
        }
    }

    /* Integer widths: best effort by type name */
    size_t sz = 0;

    if (t->kind == VT_BASE && t->name) {
        if (!strcmp(t->name,"char") || !strcmp(t->name,"signed char") || !strcmp(t->name,"unsigned char")) sz = 1;
        else if (!strcmp(t->name,"short") || !strcmp(t->name,"short int") || !strcmp(t->name,"unsigned short") || !strcmp(t->name,"unsigned short int")) sz = 2;
        else if (!strcmp(t->name,"int") || !strcmp(t->name,"unsigned int")) sz = 4;
        else if (!strcmp(t->name,"long") || !strcmp(t->name,"unsigned long") ||
                 !strcmp(t->name,"long int") || !strcmp(t->name,"unsigned long int")) sz = 8; /* x86_64 assumption */
        else if (!strcmp(t->name,"long long") || !strcmp(t->name,"unsigned long long")) sz = 8;
    }
    if (t->kind == VT_POINTER) sz = sizeof(void*);

    if (sz == 1) {
        int8_t v = 0; //memcpy(&v, addr, 1);
        if (safe_read_bytes(addr, &v, 1) != 0)
        {
            printf("[error] safe_read_bytes failed for int8 read at %p\n", addr);
            return 1;
        }
        *out = V_int((int64_t)v);
        return 0;
    }
    if (sz == 2) {
        int16_t v = 0; //memcpy(&v, addr, 2);
        if (safe_read_bytes(addr, &v, 2) != 0)
        {
            printf("[error] safe_read_bytes failed for int16 read at %p\n", addr);
            return 1;
        }
        *out = V_int((int64_t)v);
        return 0;
    }
    if (sz == 4) {
        int32_t v = 0; //memcpy(&v, addr, 4);
        if (safe_read_bytes(addr, &v, 4) != 0)
        {
            printf("[error] safe_read_bytes failed for int32 read at %p\n", addr);
            return 1;
        }
        *out = V_int((int64_t)v);
        return 0;
    }
    if (sz == 8) {
        int64_t v = 0; //memcpy(&v, addr, 8);
        if (safe_read_bytes(addr, &v, 8) != 0)
        {
            printf("[error] safe_read_bytes failed for int64 read at %p\n", addr);
            return 1;
        }
        *out = V_int(v);
        return 0;
    }

    /* fallback: old behavior */
    uint64_t vv = 0;
    if (read_u64(addr, &vv) != 0) return -3;
    *out = V_int((int64_t)vv);
    return 0;
}

/* ---------- Precompiled variable reference ---------- */

typedef enum {
    STEP_ADD_OFFSET = 1,
    STEP_DEREF_PTR  = 2,
    STEP_ADD_INDEX  = 3   // addr += index * stride
} StepKind;

typedef struct {
    StepKind kind;
    uint32_t offset;   // STEP_ADD_OFFSET uses offset
    int32_t  index;    // STEP_ADD_INDEX uses index
    uint32_t stride;   // STEP_ADD_INDEX uses stride
} AccessStep;

typedef enum {
    VREF_VALUE = 0,   // current behavior: evaluate to scalar/string
    VREF_ADDR  = 1    // address-of: evaluate to pointer/integer address
} VarRefMode;

typedef struct {
    int arg_index;            /* argN */
    ValueKind hint_kind;      /* best-effort: int/float/string */
    const VarType *final_type;/* best-effort */
    AccessStep *steps;
    size_t n_steps;

    VarRefMode mode;        // NEW: value vs address
    uint32_t extra_deref;   // NEW: number of extra deref ops from unary '*'
} VarRef;

static void varref_free(VarRef *v)
{
    if (!v) return;
    free(v->steps);
    memset(v, 0, sizeof(*v));
    v->arg_index = -1;
}

/* Compile member path into steps using DWARF VarType tree.
   - member_path is like "child.orientation" (no leading '.')

   IMPORTANT ASSUMPTION: if member_path is non-empty, argN is a POINTER VALUE
   to the struct object.
*/
static int compile_member_path_steps(const VarType *arg_type,
                                     const char *member_path,
                                     AccessStep **out_steps,
                                     size_t *out_n,
                                     const VarType **out_final_type)
{
    if (!arg_type || !member_path || !*member_path || !out_steps || !out_n) return -1;

    const VarType *t = vt_unwrap(arg_type);
    if (t && t->kind == VT_POINTER) t = vt_unwrap(t->pointee);

    AccessStep *steps = NULL;
    size_t n = 0;

    char tok[128];
    const char *p = member_path;

    while (*p) {
        p = path_next(p, tok, sizeof(tok));
        if (!tok[0]) { free(steps); return -2; }

        t = vt_unwrap(t);
        if (!t || (t->kind != VT_STRUCT && t->kind != VT_UNION)) { free(steps); return -3; }

        const StructMember *m = vt_find_member(t, tok);
        if (!m || m->offset < 0) { free(steps); return -4; }

        AccessStep *nn = (AccessStep*)realloc(steps, (n + 1) * sizeof(AccessStep));
        if (!nn) { free(steps); return -5; }
        steps = nn;
        steps[n].kind = STEP_ADD_OFFSET;
        steps[n].offset = (uint32_t)m->offset;
        steps[n].index = 0;
        steps[n].stride = 0;
        n++;

        t = m->type;

        if (*p) {
            const VarType *ut = vt_unwrap(t);
            if (ut && ut->kind == VT_POINTER) {
                nn = (AccessStep*)realloc(steps, (n + 1) * sizeof(AccessStep));
                if (!nn) { free(steps); return -6; }
                steps = nn;
                steps[n].kind = STEP_DEREF_PTR;
                steps[n].offset = 0;
                steps[n].index = 0;
                steps[n].stride = 0;
                n++;
                t = ut->pointee;
            }
        }
    }

    *out_steps = steps;
    *out_n = n;
    if (out_final_type) *out_final_type = t;
    return 0;
}

static size_t vartype_sizeof_temp(const VarType *t)
{
    t = vt_unwrap(t);
    if (!t) return 0;

    // Later should use VarType size field:
    // if (t->byte_size > 0) return (size_t)t->byte_size;

    // Fallback for common base types by name (best effort):
    if (t->kind == VT_BASE && t->name) {
        if (!strcmp(t->name,"char") || !strcmp(t->name,"signed char") || !strcmp(t->name,"unsigned char")) return 1;
        if (!strcmp(t->name,"short")|| !strcmp(t->name,"short int") || !strcmp(t->name,"unsigned short")) return 2;
        if (!strcmp(t->name,"int")  || !strcmp(t->name,"unsigned int")) return 4;
        if (!strcmp(t->name,"long") || !strcmp(t->name,"unsigned long")) return 8;  // x86_64 assumption
        if (!strcmp(t->name,"long long") || !strcmp(t->name,"unsigned long long")) return 8;
        if (!strcmp(t->name,"float")) return 4;
        if (!strcmp(t->name,"double")) return 8;
    }

    // pointers on x86_64
    if (t->kind == VT_POINTER) return sizeof(void*);

    // structs/unions: if you have a byte size, use it; otherwise unknown
    return 0;
}

static VarRef varref_from_tokens(const FuncSig *sig, const char *arg_ident, const char *member_path)
{
    VarRef r;
    memset(&r, 0, sizeof(r));
    r.arg_index = -1;
    r.hint_kind = VK_INT;
    r.final_type = NULL;
    r.mode = VREF_VALUE;
    r.extra_deref = 0;

    int idx = parse_arg_index(arg_ident);
    if (idx < 0 || !sig || (size_t)idx >= sig->n_args) return r;
    r.arg_index = idx;

    const VarType *arg_type = sig->args[idx];

    if (!member_path || !*member_path) {
        if (is_cstring_ptr(arg_type)) r.hint_kind = VK_STRING;
        else {
            const VarType *bt = vt_unwrap(arg_type);
            if (bt && bt->kind == VT_BASE && is_floatish_name(bt->name)) r.hint_kind = VK_FLOAT;
            else if (bt && bt->kind == VT_BASE && is_doubleish_name(bt->name)) r.hint_kind = VK_DOUBLE;
            else r.hint_kind = VK_INT;
        }
        r.final_type = arg_type;
        return r;
    }

    AccessStep *steps = NULL;
    size_t n = 0;
    const VarType *ft = NULL;
    if (compile_member_path_steps(arg_type, member_path, &steps, &n, &ft) != 0) {
        return r;
    }

    r.steps = steps;
    r.n_steps = n;
    r.final_type = ft;

    if (is_cstring_ptr(ft)) r.hint_kind = VK_STRING;
    else {
        const VarType *bt = vt_unwrap(ft);
        if (bt && bt->kind == VT_BASE && is_floatish_name(bt->name)) r.hint_kind = VK_FLOAT;
        else if (bt && bt->kind == VT_BASE && is_doubleish_name(bt->name)) r.hint_kind = VK_DOUBLE;
        else r.hint_kind = VK_INT;
    }

    return r;
}

static int varref_append_index(VarRef *r, int idx)
{
    if (!r) return -1;

    const VarType *t = vt_unwrap(r->final_type);
    if (!t) return -2;

    // allow indexing on:
    // - pointer-to-T : treat as base address, stride sizeof(T)
    // - array-of-T   : same idea if your VarType supports arrays
    const VarType *elem = NULL;

    if (t->kind == VT_POINTER) {
        elem = t->pointee;
    } else {
        // if you have VT_ARRAY, handle it here:
        // if (t->kind == VT_ARRAY) elem = t->elem_type;
        return -3;
    }

    size_t stride = vartype_sizeof_temp(elem);
    if (stride == 0) return -4;

    AccessStep *nn = realloc(r->steps, (r->n_steps + 1) * sizeof(AccessStep));
    if (!nn) return -5;
    r->steps = nn;

    r->steps[r->n_steps].kind = STEP_ADD_INDEX;
    r->steps[r->n_steps].index = (int32_t)idx;
    r->steps[r->n_steps].stride = (uint32_t)stride;
    r->steps[r->n_steps].offset = 0;
    r->n_steps++;

    // after indexing, the "type" becomes elem
    r->final_type = elem;

    // update hint
    if (is_cstring_ptr(r->final_type)) r->hint_kind = VK_STRING;
    else {
        const VarType *bt = vt_unwrap(r->final_type);
        if (bt && bt->kind == VT_BASE && is_floatish_name(bt->name)) r->hint_kind = VK_FLOAT;
        else if (bt && bt->kind == VT_BASE && is_doubleish_name(bt->name)) r->hint_kind = VK_DOUBLE;
        else r->hint_kind = VK_INT;
    }

    return 0;
}

static const char *read_cstring(uint64_t raw_ptr)
{
    static _Thread_local char buf[256];
    uintptr_t p = (uintptr_t)raw_ptr;
    if (!p) return "";

    size_t i = 0;
    for (; i + 1 < sizeof(buf); i++) {
        char ch = 0;
        // memcpy(&ch, (void*)(p + i), 1);
        if (safe_read_bytes((void*)(p + i), &ch, 1) != 0)
        {
            printf("[error] safe_read_bytes failed for cstring read at %p\n", (void*)(p + i));
            break;
        }
        if (ch == 0) break;
        buf[i] = ch;
    }
    buf[i] = 0;
    return buf;
}

static Value eval_varref(const VarRef *v, const FuncSig *sig, const uint64_t *raw_args)
{
    (void)sig;
    if (!v || !raw_args || v->arg_index < 0) return V_invalid();

    uint64_t raw = raw_args[v->arg_index];

    if (v->hint_kind == VK_STRING) {
        return V_str(read_cstring(raw));
    }

    if (!v->steps || v->n_steps == 0) {
        double final_val = 0.0;
        int is_floating_point = 0;

        if (v->extra_deref) {
            uint64_t addr = raw;
            const VarType *t = v->final_type;

            /* Each '*' requires that current type is pointer */
            for (uint32_t d = 0; d < v->extra_deref; d++) {
                t = vt_unwrap(t);
                if (!t || t->kind != VT_POINTER) {
                    printf("[error] extra deref on non-pointer type\n");
                    return V_invalid();
                }

                const VarType *pointee = t->pointee;

                if (d + 1 < v->extra_deref) {
                    /* intermediate deref: chase pointer */
                    void *next = NULL;
                    if (safe_read_ptr((void*)addr, &next) != 0) {
                        printf("[error] safe_read_ptr failed at %p\n", (void*)addr);
                        return V_invalid();
                    }
                    addr = (uint64_t)(uintptr_t)next;
                    if (!addr) return V_invalid();
                } else {
                    /* final deref: load scalar/struct value at addr with pointee type */
                    Value out = V_invalid();
                    ValueKind hk = VK_INT;

                    const VarType *bt = vt_unwrap(pointee);
                    if (bt && bt->kind == VT_BASE && is_floatish_name(bt->name)) hk = VK_FLOAT;
                    else if (bt && bt->kind == VT_BASE && is_doubleish_name(bt->name)) hk = VK_DOUBLE;

                    if (read_scalar_value((void*)addr, pointee, hk, &out) != 0) {
                        printf("[error] read_scalar_value failed at %p\n", (void*)addr);
                        return V_invalid();
                    }
                    return out;
                }

                t = pointee;
            }

            return V_invalid(); /* shouldn't reach */
        }

        if (v->hint_kind == VK_FLOAT) {
            /* Case 1: 32-bit Float */
            /* Take the lower 32 bits of the 64-bit register */
            uint32_t bits = (uint32_t)raw; 
            float f_temp;
            
            /* Reinterpret bits as float */
            if (safe_read_bytes(&bits, &f_temp, sizeof(f_temp)) != 0)
            {
                printf("[error] safe_read_bytes failed for float reinterpret at %p\n", (void*)&bits);
                return V_invalid();
            }
            
            /* Promote to double for V_float */
            final_val = (double)f_temp; 
            is_floating_point = 1;
        } 
        else if (v->hint_kind == VK_DOUBLE) { 
            /* Case 2: 64-bit Double */
            /* Reinterpret the full 64-bit register as double */
            if (safe_read_bytes(&raw, &final_val, sizeof(final_val)) != 0)
            {
                printf("[error] safe_read_bytes failed for double reinterpret at %p\n", (void*)&raw);
                return V_invalid();
            }
            is_floating_point = 1;
        }
        
        if (is_floating_point) {
            return V_float(final_val);
        }

        return V_int((int64_t)raw);
    }

    uintptr_t addr = (uintptr_t)raw;

    for (size_t i = 0; i < v->n_steps; i++) {
        const AccessStep *st = &v->steps[i];
        if (st->kind == STEP_ADD_OFFSET) {
            addr += (uintptr_t)st->offset;
        } else if (st->kind == STEP_DEREF_PTR) {
            void *next = NULL;
            if (safe_read_ptr((void*)addr, &next) != 0)
            {
                printf("[error] safe_read_ptr failed for deref at %p\n", (void*)addr);
                return V_invalid();
            }
            addr = (uintptr_t)next;
            if (!addr) return V_invalid();
        } else if (st->kind == STEP_ADD_INDEX) {
            addr += (uintptr_t)((int64_t)st->index * (int64_t)st->stride);
        }
    }

    for (uint32_t k = 0; k < v->extra_deref; k++) {
        void *next = NULL;
        if (safe_read_ptr((void*)addr, &next) != 0)
        {
            printf("[error] safe_read_ptr failed for extra deref at %p\n", (void*)addr);
            return V_invalid();
        }
        addr = (uintptr_t)next;
        if (!addr) return V_invalid();
    }

    if (v->mode == VREF_ADDR) {
        // return address as int
        return V_int((int64_t)(uintptr_t)addr);
    }

    Value out = V_invalid();
    if (read_scalar_value((void*)addr, v->final_type, v->hint_kind, &out) != 0)
        return V_invalid();
    return out;
}

/* ---------- Tokenizer for trigger language ---------- */

typedef enum {
    TK_EOF=0,
    TK_LPAREN, TK_RPAREN,
    TK_AND, TK_OR,
    TK_EQ, TK_NE, TK_LT, TK_LE, TK_GT, TK_GE,
    TK_ASSIGN,
    TK_NUMBER,
    TK_FLOAT,
    TK_STRING,
    TK_IDENT,
    TK_DOT,
    TK_STAR, TK_AMP, TK_LBRACK, TK_RBRACK,
    TK_ARROW
} TokKind;

typedef struct {
    TokKind kind;
    int64_t  i;
    double   f;
    char     text[512];
} Token;

typedef struct {
    const char *s;
    size_t i;
    Token cur;
} Lexer;

static void lex_skip_ws(Lexer *L){ while (L->s[L->i] && isspace((unsigned char)L->s[L->i])) L->i++; }
static int  lex_peek(Lexer *L){ return (unsigned char)L->s[L->i]; }

static void lex_read_quoted(Lexer *L, char quote_char)
{
    /* assume current char is quote_char */
    L->i++; /* skip opening quote */

    size_t k = 0;
    while (L->s[L->i] && L->s[L->i] != quote_char) {
        char ch = L->s[L->i++];

        /* Optional: basic escapes in double quotes, and allow \' inside single quotes */
        if (ch == '\\' && L->s[L->i]) {
            char e = L->s[L->i++];
            if (e == 'n') ch = '\n';
            else if (e == 't') ch = '\t';
            else if (e == 'r') ch = '\r';
            else if (e == '\\') ch = '\\';
            else if (e == '"' ) ch = '"';
            else if (e == '\'') ch = '\'';
            else ch = e; /* fallback: literal */
        }

        if (k + 1 < sizeof(L->cur.text)) L->cur.text[k++] = ch;
    }

    /* consume closing quote if present */
    if (L->s[L->i] == quote_char) L->i++;

    L->cur.text[k] = 0;
    L->cur.kind = TK_STRING;
}


static void lex_next(Lexer *L)
{
    lex_skip_ws(L);
    int c = lex_peek(L);

    memset(&L->cur, 0, sizeof(L->cur));
    if (!c) { L->cur.kind = TK_EOF; return; }

    if (c=='&' && L->s[L->i+1]=='&') { L->i+=2; L->cur.kind=TK_AND; return; }
    if (c=='|' && L->s[L->i+1]=='|') { L->i+=2; L->cur.kind=TK_OR;  return; }
    if (c=='=' && L->s[L->i+1]=='=') { L->i+=2; L->cur.kind=TK_EQ;  return; }
    if (c=='!' && L->s[L->i+1]=='=') { L->i+=2; L->cur.kind=TK_NE;  return; }
    if (c=='<' && L->s[L->i+1]=='=') { L->i+=2; L->cur.kind=TK_LE;  return; }
    if (c=='>' && L->s[L->i+1]=='=') { L->i+=2; L->cur.kind=TK_GE;  return; }
    if (c=='-' && L->s[L->i+1]=='>') { L->i+=2; L->cur.kind=TK_ARROW; return; }
    
    if (c=='(') { L->i++; L->cur.kind=TK_LPAREN; return; }
    if (c==')') { L->i++; L->cur.kind=TK_RPAREN; return; }
    if (c=='<') { L->i++; L->cur.kind=TK_LT; return; }
    if (c=='>') { L->i++; L->cur.kind=TK_GT; return; }
    if (c=='.') { L->i++; L->cur.kind=TK_DOT; return; }
    if (c=='=') { L->i++; L->cur.kind=TK_ASSIGN; return; }
    if (c=='&') { L->i++; L->cur.kind=TK_AMP; return; }
    if (c=='*') { L->i++; L->cur.kind=TK_STAR; return; }
    if (c=='[') { L->i++; L->cur.kind=TK_LBRACK; return; }
    if (c==']') { L->i++; L->cur.kind=TK_RBRACK; return; }

    if (c == '"')  { lex_read_quoted(L, '"');  return; }
    if (c == '\'') { lex_read_quoted(L, '\''); return; }

    if (isdigit(c)) {
        size_t start = L->i;
        int is_hex = (c=='0' && (L->s[L->i+1]=='x' || L->s[L->i+1]=='X'));
        int has_dot = 0;

        if (is_hex) {
            L->i += 2;
            while (isxdigit((unsigned char)L->s[L->i])) L->i++;
            size_t n = L->i - start;
            char tmp[128];
            if (n >= sizeof(tmp)) n = sizeof(tmp)-1;
            // memcpy(tmp, L->s+start, n); tmp[n]=0;
            if (safe_read_bytes(L->s+start, tmp, n) != 0)
            {
                printf("[error] safe_read_bytes failed for hex number read\n");
                L->cur.kind = TK_EOF;
                return;
            }
            L->cur.kind = TK_NUMBER;
            L->cur.i = (int64_t)strtoll(tmp, NULL, 16);
            return;
        }

        while (isdigit((unsigned char)L->s[L->i]) || L->s[L->i]=='.') {
            if (L->s[L->i]=='.') has_dot = 1;
            L->i++;
        }
        size_t n = L->i - start;
        char tmp[128];
        if (n >= sizeof(tmp)) n = sizeof(tmp)-1;
        // memcpy(tmp, L->s+start, n); tmp[n]=0;
        if (safe_read_bytes(L->s+start, tmp, n) != 0)
        {
            printf("[error] safe_read_bytes failed for decimal number read\n");
            L->cur.kind = TK_EOF;
            return;
        }
        tmp[n] = 0;

        if (has_dot) {
            L->cur.kind = TK_FLOAT;
            L->cur.f = strtod(tmp, NULL);
        } else {
            L->cur.kind = TK_NUMBER;
            L->cur.i = (int64_t)strtoll(tmp, NULL, 10);
        }
        return;
    }

    if (isalpha(c) || c=='_') {
        size_t k=0;
        while (L->s[L->i] && (isalnum((unsigned char)L->s[L->i]) || L->s[L->i]=='_')) {
            if (k + 1 < sizeof(L->cur.text)) L->cur.text[k++] = L->s[L->i];
            L->i++;
        }
        L->cur.text[k]=0;
        L->cur.kind = TK_IDENT;
        return;
    }

    L->i++;
    L->cur.kind = TK_EOF;
}

/* ---------- Compiled AST ---------- */

typedef enum {
    OP_EQ, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE
} CmpOp;

typedef enum {
    N_CONST,
    N_VAR,
    N_CMP,
    N_AND,
    N_OR
} NodeKind;

typedef struct Node Node;

struct Node {
    NodeKind kind;
    union {
        Value cval;      /* N_CONST */
        VarRef vref;     /* N_VAR */
        struct { CmpOp op; Node *l; Node *r; } cmp; /* N_CMP */
        struct { Node *l; Node *r; } lr;            /* N_AND/N_OR */
    } u;
};

static void free_value_literal(Value v)
{
    if (v.kind == VK_STRING) free((void*)v.v.s);
}

static void node_free(Node *n)
{
    if (!n) return;
    switch (n->kind) {
        case N_CONST:
            free_value_literal(n->u.cval);
            break;
        case N_VAR:
            varref_free(&n->u.vref);
            break;
        case N_CMP:
            node_free(n->u.cmp.l);
            node_free(n->u.cmp.r);
            break;
        case N_AND:
        case N_OR:
            node_free(n->u.lr.l);
            node_free(n->u.lr.r);
            break;
    }
    free(n);
}

void compiled_trigger_free(CompiledTrigger *t)
{
    if (!t) return;
    node_free(t->root);
    free(t->expr_owned);
    memset(t, 0, sizeof(*t));
}

static CmpOp tok_to_cmp(TokKind k)
{
    if (k == TK_ASSIGN || k == TK_EQ) return OP_EQ;
    if (k == TK_NE) return OP_NE;
    if (k == TK_LT) return OP_LT;
    if (k == TK_LE) return OP_LE;
    if (k == TK_GT) return OP_GT;
    return OP_GE;
}

typedef struct {
    Lexer L;
    const FuncSig *sig;
} CParser;

static Node *parse_ast_expr(CParser *P);

static Node *node_new(NodeKind k)
{
    Node *n = (Node*)calloc(1, sizeof(Node));
    if (n) n->kind = k;
    if (n && k == N_VAR) n->u.vref.arg_index = -1;
    return n;
}

static void cconsume(CParser *P, TokKind k)
{
    if (P->L.cur.kind == k) lex_next(&P->L);
}

static Node *parse_ast_primary(CParser *P)
{
    if (!P) return NULL;

    /* Handle prefix ops first (so *arg0... works) */
    int saw_addr = 0;
    int deref_count = 0;
    while (P->L.cur.kind == TK_AMP || P->L.cur.kind == TK_STAR) {
        if (P->L.cur.kind == TK_AMP) saw_addr = 1;
        else deref_count++;
        lex_next(&P->L);
    }

    Token t = P->L.cur;

    if (t.kind == TK_NUMBER) {
        /* Disallow prefix ops on non-lvalues in your minimal language */
        if (saw_addr || deref_count) return NULL;

        Node *n = node_new(N_CONST);
        if (!n) return NULL;
        n->u.cval = V_int(t.i);
        lex_next(&P->L);
        return n;
    }

    if (t.kind == TK_FLOAT) {
        if (saw_addr || deref_count) return NULL;

        Node *n = node_new(N_CONST);
        if (!n) return NULL;
        n->u.cval = V_float(t.f);
        lex_next(&P->L);
        return n;
    }

    if (t.kind == TK_STRING) {
        if (saw_addr || deref_count) return NULL;

        Node *n = node_new(N_CONST);
        if (!n) return NULL;
        n->u.cval = V_str(xstrdup(t.text));
        lex_next(&P->L);
        return n;
    }

    if (t.kind == TK_IDENT) {
        /* Support NULL literal */
        if (strcmp(t.text, "NULL") == 0 || strcmp(t.text, "null") == 0) {
            if (saw_addr || deref_count) return NULL;  /* keep your rule */
            Node *n = node_new(N_CONST);
            if (!n) return NULL;
            n->u.cval = V_int(0);
            lex_next(&P->L);
            return n;
        }

        /* parse args and member paths */
        char arg_ident[256];
        strncpy(arg_ident, t.text, sizeof(arg_ident));
        arg_ident[sizeof(arg_ident)-1] = 0;
        lex_next(&P->L);

        /* Collect member path + constant indices (allow mixing: a.b[3].c) */
        char path[512]; path[0] = 0;
        int idxs[16]; int nidx = 0;

        for (;;) {
            if (P->L.cur.kind == TK_DOT || P->L.cur.kind == TK_ARROW) {
                lex_next(&P->L);
                if (P->L.cur.kind != TK_IDENT) return NULL; /* strict */
                if (path[0]) strncat(path, ".", sizeof(path)-strlen(path)-1);
                strncat(path, P->L.cur.text, sizeof(path)-strlen(path)-1);
                lex_next(&P->L);
                continue;
            }

            if (P->L.cur.kind == TK_LBRACK) {
                lex_next(&P->L);
                if (P->L.cur.kind != TK_NUMBER) return NULL; /* const index only */
                if (nidx < (int)(sizeof(idxs)/sizeof(idxs[0]))) {
                    idxs[nidx++] = (int)P->L.cur.i;
                } else {
                    return NULL;
                }
                lex_next(&P->L);
                if (P->L.cur.kind != TK_RBRACK) return NULL;
                lex_next(&P->L);
                continue;
            }

            break;
        }

        Node *n = node_new(N_VAR);
        if (!n) return NULL;

        n->u.vref = varref_from_tokens(P->sig, arg_ident, path[0] ? path : NULL);
        if (n->u.vref.arg_index < 0) { node_free(n); return NULL; }

        for (int k = 0; k < nidx; k++) {
            if (varref_append_index(&n->u.vref, idxs[k]) != 0) {
                node_free(n);
                return NULL;
            }
        }

        /* Apply prefix ops to this VarRef */
        if (saw_addr) {
            n->u.vref.mode = VREF_ADDR;
            if (deref_count > 0) { node_free(n); return NULL; } /* keep simple */
        } else {
            n->u.vref.extra_deref = (uint32_t)deref_count;
        }

        return n;
    }

    if (t.kind == TK_LPAREN) {
        /* In minimal design: disallow prefix ops on (...) */
        if (saw_addr || deref_count) return NULL;

        lex_next(&P->L);
        Node *e = parse_ast_expr(P);
        cconsume(P, TK_RPAREN);
        return e;
    }

    /* Unknown token */
    return NULL;
}

static Node *parse_ast_cmp(CParser *P)
{
    Node *left = parse_ast_primary(P);
    if (!left) printf("[parse] null node returned from primary\n");
    if (!left) return NULL;

    TokKind op = P->L.cur.kind;
    if (op==TK_EQ || op==TK_NE || op==TK_LT || op==TK_LE || op==TK_GT || op==TK_GE || op==TK_ASSIGN) {
        lex_next(&P->L);
        Node *right = parse_ast_primary(P);
        if (!right) { node_free(left); return NULL; }

        Node *n = node_new(N_CMP);
        if (!n) { node_free(left); node_free(right); return NULL; }
        n->u.cmp.op = tok_to_cmp(op);
        n->u.cmp.l = left;
        n->u.cmp.r = right;
        return n;
    }

    return left;
}

static Node *parse_ast_and(CParser *P)
{
    Node *n = parse_ast_cmp(P);
    if (!n) printf("[parse] null node returned from CMP\n");
    if (!n) return NULL;

    while (P->L.cur.kind == TK_AND) {
        lex_next(&P->L);
        Node *r = parse_ast_cmp(P);
        if (!r) { node_free(n); return NULL; }
        Node *p = node_new(N_AND);
        if (!p) { node_free(n); node_free(r); return NULL; }
        p->u.lr.l = n;
        p->u.lr.r = r;
        n = p;
    }

    return n;
}

static Node *parse_ast_or(CParser *P)
{
    Node *n = parse_ast_and(P);
    if (!n) printf("[parse] null node returned from AND\n");
    if (!n) return NULL;

    while (P->L.cur.kind == TK_OR) {
        lex_next(&P->L);
        Node *r = parse_ast_and(P);
        if (!r) { node_free(n); return NULL; }
        Node *p = node_new(N_OR);
        if (!p) { node_free(n); node_free(r); return NULL; }
        p->u.lr.l = n;
        p->u.lr.r = r;
        n = p;
    }

    return n;
}

static Node *parse_ast_expr(CParser *P) { return parse_ast_or(P); }

int compile_trigger(CompiledTrigger *out, const char *expr, const FuncSig *sig)
{
    if (!out || !expr || !sig) return -1;
    memset(out, 0, sizeof(*out));
    out->expr_owned = xstrdup(expr);

    CParser P;
    memset(&P, 0, sizeof(P));
    P.sig = sig;
    P.L.s = expr;
    P.L.i = 0;
    lex_next(&P.L);

    out->root = parse_ast_expr(&P);
    if (!out->root) return -2;
    return 0;
}

static int cmp_values(CmpOp op, Value a, Value b)
{
    if (a.kind == VK_STRING || b.kind == VK_STRING) {
        const char *as = (a.kind == VK_STRING) ? a.v.s : "";
        const char *bs = (b.kind == VK_STRING) ? b.v.s : "";
        int eq = (strcmp(as, bs) == 0);
        if (op == OP_EQ) return eq;
        if (op == OP_NE) return !eq;
        return 0;
    }

    if (a.kind == VK_FLOAT && b.kind == VK_FLOAT) {
        float x = (a.kind == VK_FLOAT) ? (float)a.v.f : (float)a.v.i;
        float y = (b.kind == VK_FLOAT) ? (float)b.v.f : (float)b.v.i;
        switch (op) {
            case OP_EQ: return x == y;
            case OP_NE: return x != y;
            case OP_LT: return x <  y;
            case OP_LE: return x <= y;
            case OP_GT: return x >  y;
            case OP_GE: return x >= y;
        }
        return 0;
    }
    
    if (a.kind == VK_DOUBLE || b.kind == VK_DOUBLE) {
        double x = (a.kind == VK_DOUBLE) ? (double)a.v.f : (double)a.v.i;
        double y = (b.kind == VK_DOUBLE) ? (double)b.v.f : (double)b.v.i;
        switch (op) {
            case OP_EQ: return x == y;
            case OP_NE: return x != y;
            case OP_LT: return x <  y;
            case OP_LE: return x <= y;
            case OP_GT: return x >  y;
            case OP_GE: return x >= y;
        }
        return 0;
    }

    int64_t x = (a.kind == VK_INT) ? a.v.i : 0;
    int64_t y = (b.kind == VK_INT) ? b.v.i : 0;
    switch (op) {
        case OP_EQ: return x == y;
        case OP_NE: return x != y;
        case OP_LT: return x <  y;
        case OP_LE: return x <= y;
        case OP_GT: return x >  y;
        case OP_GE: return x >= y;
    }
    return 0;
}

static Value eval_node(const Node *n, const FuncSig *sig, const uint64_t *raw_args)
{
    if (!n) return V_invalid();

    switch (n->kind) {
        case N_CONST:
            return n->u.cval;

        case N_VAR:
            return eval_varref(&n->u.vref, sig, raw_args);

        case N_CMP: {
            Value a = eval_node(n->u.cmp.l, sig, raw_args);
            Value b = eval_node(n->u.cmp.r, sig, raw_args);
            // printf("[eval] CMP node: op=%d a=", n->u.cmp.op);
            // if (a.kind == VK_INT) printf("INT(%lld)", (long long)a.v.i);
            // else if (a.kind == VK_FLOAT) printf("FLOAT(%f)", a.v.f);
            // else if (a.kind == VK_STRING) printf("STRING(\"%s\")", a.v.s);
            // else printf("INVALID");
            // printf(" b=");
            // if (b.kind == VK_INT) printf("INT(%lld)", (long long)b.v.i);
            // else if (b.kind == VK_FLOAT) printf("FLOAT(%f)", b.v.f);
            // else if (b.kind == VK_STRING) printf("STRING(\"%s\")", b.v.s);
            // else printf("INVALID");
            // printf("\n");
            return V_bool(cmp_values(n->u.cmp.op, a, b));
        }

        case N_AND: {
            Value a = eval_node(n->u.lr.l, sig, raw_args);
            if (!value_truthy(a)) return V_bool(0);
            Value b = eval_node(n->u.lr.r, sig, raw_args);
            return V_bool(value_truthy(b));
        }

        case N_OR: {
            Value a = eval_node(n->u.lr.l, sig, raw_args);
            if (value_truthy(a)) return V_bool(1);
            Value b = eval_node(n->u.lr.r, sig, raw_args);
            return V_bool(value_truthy(b));
        }
    }

    return V_invalid();
}

int eval_compiled_trigger(const CompiledTrigger *t, const FuncSig *sig, const uint64_t *raw_args)
{
    if (!t || !t->root || !sig || !raw_args) return 0;
    Value r = eval_node(t->root, sig, raw_args);
    return value_truthy(r);
}

/* ======================= Demo pipeline usage ======================= */
static void mark_need_args(const Node *n, uint8_t *need_dummy, size_t n_args)
{
    if (!n) return;
    switch (n->kind) {
        case N_VAR:
            if (n->u.vref.arg_index >= 0 && (size_t)n->u.vref.arg_index < n_args) {
                if (n->u.vref.n_steps > 0)
                    need_dummy[n->u.vref.arg_index] = 1;
            }
            break;
        case N_CMP:
            mark_need_args(n->u.cmp.l, need_dummy, n_args);
            mark_need_args(n->u.cmp.r, need_dummy, n_args);
            break;
        case N_AND:
        case N_OR:
            mark_need_args(n->u.lr.l, need_dummy, n_args);
            mark_need_args(n->u.lr.r, need_dummy, n_args);
            break;
        case N_CONST:
            break;
    }
}

void demo_pipeline(const char *func_name)
{
    DwarfModel *model = dwarf_scan_collect_model();
    if (!model) {
        printf("[demo] failed to build DWARF model\n");
        return;
    }

    const FuncSig *f = find_funcsig_by_name(model, func_name);
    if (!f) {
        printf("[demo] function not found: %s\n", func_name);
        dwarf_model_free(model);
        return;
    }

    printf("[demo] found function %s with %zu args\n", f->name, f->n_args);

    const char *cfg_path = getenv("TRACE_CONFIG");
    if (!cfg_path) cfg_path = "config.yaml";

    TraceConditionCfg cfg;
    if (load_trace_config(cfg_path, &cfg) != 0) {
        printf("[demo] failed to load %s\n", cfg_path);
        dwarf_model_free(model);
        return;
    }

    const TargetCfg *t = cfg_find_target(&cfg, func_name);
    if (!t) {
        printf("[demo] no target rule for %s\n", func_name);
        cfg_free(&cfg);
        dwarf_model_free(model);
        return;
    }

    printf("[demo] loaded %zu trigger(s) for %s\n", t->triggers.n, func_name);

    CompiledTrigger *compiled = NULL;
    if (t->triggers.n) {
        compiled = (CompiledTrigger*)calloc(t->triggers.n, sizeof(CompiledTrigger));
        if (!compiled) {
            cfg_free(&cfg);
            dwarf_model_free(model);
            return;
        }
        for (size_t k = 0; k < t->triggers.n; k++) {
            if (compile_trigger(&compiled[k], t->triggers.items[k], f) != 0) {
                printf("[demo] failed to compile trigger[%zu]: %s\n", k, t->triggers.items[k]);
            }
        }
    }

    /* Mark which args need a valid dummy address (any VarRef using member steps). */
    uint8_t *need_dummy = (uint8_t*)calloc(f->n_args, 1);
    if (!need_dummy) {
        if (compiled) {
            for (size_t k = 0; k < t->triggers.n; k++) compiled_trigger_free(&compiled[k]);
            free(compiled);
        }
        cfg_free(&cfg);
        dwarf_model_free(model);
        return;
    }

    /* Mark needed dummy args */

    if (compiled) {
        for (size_t k = 0; k < t->triggers.n; k++)
            mark_need_args(compiled[k].root, need_dummy, f->n_args);
    }

    uint64_t *raw_args = (uint64_t*)calloc(f->n_args, sizeof(uint64_t));
    void **dummy_blocks = (void**)calloc(f->n_args, sizeof(void*));
    if (!raw_args || !dummy_blocks) {
        free(raw_args);
        free(dummy_blocks);
        free(need_dummy);
        if (compiled) {
            for (size_t k = 0; k < t->triggers.n; k++) compiled_trigger_free(&compiled[k]);
            free(compiled);
        }
        cfg_free(&cfg);
        dwarf_model_free(model);
        return;
    }

    for (size_t i = 0; i < f->n_args; i++) {
        if (need_dummy[i]) {
            /* Needs to be a valid address because eval_varref may dereference/offset into it. */
            dummy_blocks[i] = calloc(1, 256);
            raw_args[i] = (uint64_t)dummy_blocks[i];
        } else {
            /* Scalar-ish fake */
            raw_args[i] = (uint64_t)(0x1000 + i * 0x10);
            if (i == 0) raw_args[i] = 10; // for demo
            if (i == 1) raw_args[i] = 19; // for demo
        }
    }

    for (size_t k = 0; k < t->triggers.n; k++) {
        int ok = eval_compiled_trigger(&compiled[k], f, raw_args);
        printf("  trigger[%zu] %s => %s\n", k,
               compiled[k].expr_owned ? compiled[k].expr_owned : "<expr>",
               ok ? "TRUE" : "FALSE");
    }
    
    struct timespec time;
    timer_start(&time);

    for (int i = 0; i < 1000000; i++)
        eval_compiled_trigger(&compiled[0], f, raw_args);

    timer_end(&time, "1M compiled evals", 1000000);


    for (size_t i = 0; i < f->n_args; i++) free(dummy_blocks[i]);
    free(dummy_blocks);
    free(raw_args);
    free(need_dummy);

    if (compiled) {
        for (size_t k = 0; k < t->triggers.n; k++) compiled_trigger_free(&compiled[k]);
        free(compiled);
    }
    cfg_free(&cfg);
    dwarf_model_free(model);
}

/* ======================= LD_PRELOAD Demo ======================= */

// static DwarfModel *model = NULL;

// /* Runs when the .so is loaded */
// __attribute__((constructor))
// static void dwuser_on_load(void)
// {
//     fprintf(stderr, "[function] loaded via LD_PRELOAD\n");

//     model = dwarf_scan_collect_model();
//     if (!model) {
//         fprintf(stderr, "[function] dwarf_scan_collect_model() failed\n");
//         return;
//     }

//     /* Just as a demo: print one known function */
//     // print_function_by_name("update_tree");
//     demo_pipeline("price_out_impl");
// }

// /* Runs when the program exits */
// __attribute__((destructor))
// static void dwuser_on_unload(void)
// {
//     fprintf(stderr, "[function] unloading\n");
//     dwarf_model_free(model);
//     model = NULL;
// }


// gcc -shared -fPIC trigger_compiler.c trace_config.c -o trigger_compiler.so -I. -L. -ldwscan -Wl,-rpath,'$ORIGIN' -lyaml
// LD_PRELOAD=./trigger_compiler.so ~/Codes/cpu2017/benchspec/CPU/505.mcf_r/run/run_base_refrate_ali-test1-m64.0000/mcf_r_base.ali-test1-m64