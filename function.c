#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "libdwscan.h"


/* ======================= Helpers ======================= */

static const VarType *vt_unwrap(const VarType *v)
{
    while (v && (v->kind == VT_TYPEDEF || v->kind == VT_QUALIFIER))
        v = v->under;
    return v;
}

/* If v is pointer -> peel to pointee for type reasoning (no deref). */
static const VarType *peel_ptr_for_type(const VarType *v) {
    v = vt_unwrap(v);
    if (v && v->kind == VT_POINTER) v = v->pointee;
    return vt_unwrap(v);
}

/* Recursively: if struct/union -> take first member -> repeat until base/enum/pointer/etc. */
static const VarType *first_base_type(const VarType *v) {
    v = peel_ptr_for_type(v);
    for (int depth = 0; v && depth < 64; depth++) {
        if (v->kind == VT_STRUCT || v->kind == VT_UNION) {
            if (!v->members || v->n_members == 0) return v;  // incomplete type
            v = v->members[0].type;
            v = peel_ptr_for_type(v);
            continue;
        }
        return v;
    }
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

/* ======================= Core API ======================= */

/*
   Resolve a.b.c starting from (base_addr, base_type)
   Follows pointers automatically.
*/
int resolve_member_path(void *base_addr,
                        const VarType *base_type,
                        const char *path,
                        void **out_addr,
                        const VarType **out_type)
{
    if (!base_addr || !base_type || !path) return -1;

    const VarType *t = base_type;
    void *addr = base_addr;
    char tok[128];

    const char *p = path;
    while (*p) {
        p = path_next(p, tok, sizeof(tok));
        if (!tok[0]) return -2;

        t = vt_unwrap(t);

        if (t->kind == VT_POINTER) {
            memcpy(&addr, addr, sizeof(void*));
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

/* ======================= Comparison ======================= */
static uint64_t prng_u64(void) {
    static uint64_t s = 0x12345678abcdefULL;
    s ^= s << 7;
    s ^= s >> 9;
    s ^= s << 8;
    return s;
}

static float prng_f32(void) {
    /* 24-bit mantissa-ish fraction from PRNG */
    uint32_t x = (uint32_t)(prng_u64() & 0x00FFFFFFu);
    return (float)x / (float)0x01000000u;  // [0,1)
}

/* Best-effort “is this name a float type?” */
static int name_is_float(const char *n) {
    if (!n) return 0;
    return (strcmp(n, "float") == 0);
}
static int name_is_double(const char *n) {
    if (!n) return 0;
    return (strcmp(n, "double") == 0);
}

/* Best-effort “is this name an integer-ish type?” */
static int name_is_signed_int(const char *n) {
    if (!n) return 0;
    return (!strcmp(n,"char") || !strcmp(n,"short") || !strcmp(n,"int") ||
            !strcmp(n,"long") || !strcmp(n,"long int") || !strcmp(n,"long long") ||
            !strcmp(n,"int8_t") || !strcmp(n,"int16_t") || !strcmp(n,"int32_t") || !strcmp(n,"int64_t"));
}
static int name_is_unsigned_int(const char *n) {
    if (!n) return 0;
    return (!strcmp(n,"unsigned char") || !strcmp(n,"unsigned short") || !strcmp(n,"unsigned") ||
            !strcmp(n,"unsigned int") || !strcmp(n,"unsigned long") || !strcmp(n,"unsigned long long") ||
            !strcmp(n,"uint8_t") || !strcmp(n,"uint16_t") || !strcmp(n,"uint32_t") || !strcmp(n,"uint64_t") ||
            !strcmp(n,"size_t"));
}

/* Produce a random value “shaped like” vt. Returns 64-bit payload for demo/compare. */
static uint64_t random_like_type(const VarType *vt)
{
    const VarType *t = first_base_type(vt);
    t = vt_unwrap(t);

    float f = prng_f32();  // base random
    const char *n = t ? t->name : NULL;

    if (!t) return prng_u64();

    if (t->kind == VT_POINTER) {
        /* demo: fake aligned address */
        return (prng_u64() & 0x0000FFFFFFFFF000ULL);
    }

    if (t->kind == VT_ENUM || t->kind == VT_BASE) {
        if (name_is_float(n)) {
            float x = (float)(f * 1000.0f);
            uint32_t bits;
            memcpy(&bits, &x, sizeof(bits));
            return (uint64_t)bits; // store in low bits
        }
        if (name_is_double(n)) {
            double x = (double)(f * 1000.0);
            uint64_t bits;
            memcpy(&bits, &x, sizeof(bits));
            return bits;
        }

        if (name_is_signed_int(n)) {
            /* map to a moderate signed range for demo */
            int64_t x = (int64_t)((f - 0.5f) * 2000000.0f);
            return (uint64_t)x;
        }
        if (name_is_unsigned_int(n)) {
            uint64_t x = (uint64_t)(f * 2000000.0f);
            return x;
        }

        /* fallback */
        return prng_u64();
    }

    /* If it’s still struct/union etc (incomplete), just fallback */
    return prng_u64();
}

static void compare_fake_vs_random(const VarType *arg_type, uint64_t fake_raw)
{
    uint64_t rnd = random_like_type(arg_type);

    /* For demo: compare numeric closeness for float/double, exact match for ints */
    const VarType *t = first_base_type(arg_type);
    t = vt_unwrap(t);
    const char *n = t ? t->name : NULL;

    if (t && t->kind == VT_BASE && name_is_float(n)) {
        float a, b;
        uint32_t aa = (uint32_t)fake_raw;
        uint32_t bb = (uint32_t)rnd;
        memcpy(&a, &aa, sizeof(a));
        memcpy(&b, &bb, sizeof(b));
        printf("    compare(float): fake=%f rnd=%f diff=%f\n", a, b, (a-b));
        return;
    }

    if (t && t->kind == VT_BASE && name_is_double(n)) {
        double a, b;
        memcpy(&a, &fake_raw, sizeof(a));
        memcpy(&b, &rnd, sizeof(b));
        printf("    compare(double): fake=%f rnd=%f diff=%f\n", a, b, (a-b));
        return;
    }

    /* default int/ptr compare */
    printf("    compare: fake=%#llx rnd=%#llx eq=%s\n",
           (unsigned long long)fake_raw,
           (unsigned long long)rnd,
           (fake_raw == rnd ? "yes" : "no"));
}

/* ======================= Demo Pipeline ======================= */

/* Read raw 64-bit scalar safely (no casting) */
int read_u64(void *addr, uint64_t *out)
{
    // if (!addr || !out) return -1;
    // memcpy(out, addr, sizeof(uint64_t));
    // return 0;
    (void)addr; /* not used for now */
    if (!out) return -1;

    /* TEMPORARY: return a random value to demonstrate the pipeline */
    static uint64_t seed = 0x12345678abcdefULL;
    seed ^= seed << 7;
    seed ^= seed >> 9;
    seed ^= seed << 8;
    *out = seed;
    return 0;
}

void demo_pipeline(const char *func_name)
{
    DwarfModel *model = dwarf_scan_collect_model();
    if (!model) {
        printf("[demo] failed to build DWARF model\n");
        return;
    }

    /* Locate the function signature via libdwscan */
    const FuncSig *f = find_funcsig_by_name(model, func_name);
    if (!f) {
        printf("[demo] function not found: %s\n", func_name);
        dwarf_model_free(model);
        return;
    }
    print_funcsig(f);

    printf("[demo] found function %s with %zu args\n", f->name, f->n_args);

    /* Compare against fake runtime args */
    for (size_t i = 0; i < f->n_args; i++) {
        uint64_t fake;
        read_u64(NULL, &fake);
        compare_fake_vs_random(f->args[i], fake);
    }

    dwarf_model_free(model);
}



/* ======================= LD_PRELOAD Demo ======================= */

static DwarfModel *model = NULL;

/* Runs when the .so is loaded */
__attribute__((constructor))
static void dwuser_on_load(void)
{
    fprintf(stderr, "[function] loaded via LD_PRELOAD\n");

    model = dwarf_scan_collect_model();
    if (!model) {
        fprintf(stderr, "[function] dwarf_scan_collect_model() failed\n");
        return;
    }

    /* Just as a demo: print one known function */
    // print_function_by_name("update_tree");
    demo_pipeline("update_tree");
}

/* Runs when the program exits */
__attribute__((destructor))
static void dwuser_on_unload(void)
{
    fprintf(stderr, "[function] unloading\n");
    dwarf_model_free(model);
    model = NULL;
}

// gcc -shared -fPIC function.c -o function.so -I. -L. -ldwscan -Wl,-rpath,'$ORIGIN'
// LD_PRELOAD=./function.so ~/Codes/cpu2017/benchspec/CPU/505.mcf_r/run/run_base_refrate_ali-test1-m64.0000/mcf_r_base.ali-test1-m64