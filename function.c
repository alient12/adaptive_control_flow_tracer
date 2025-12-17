#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>

#include "libdwscan.h"
#include "trace_config.h"

/* =================== Timing helpers ==================== */
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

/* ======================= Helpers ======================= */

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

/* ======================= Core API ======================= */

int resolve_member_path(void *base_addr,
                        const VarType *base_type,
                        const char *path,
                        void **out_addr,
                        const VarType **out_type)
{
    if (!base_addr || !base_type || !path || !out_addr || !out_type) return -1;

    const VarType *t = vt_unwrap(base_type);
    void *addr = base_addr;

    /* IMPORTANT: base_addr is a pointer VALUE for pointer args */
    if (t && t->kind == VT_POINTER) {
        t = vt_unwrap(t->pointee);
        /* addr stays as-is: points to the struct object */
    }

    char tok[128];
    const char *p = path;

    while (*p) {
        p = path_next(p, tok, sizeof(tok));
        if (!tok[0]) return -2;

        t = vt_unwrap(t);
        if (!t || (t->kind != VT_STRUCT && t->kind != VT_UNION)) return -4;

        const StructMember *m = vt_find_member(t, tok);
        if (!m || m->offset < 0) return -5;

        addr = (uint8_t*)addr + (size_t)m->offset;
        t = m->type;

        /* If there is more path to traverse and current field is a pointer,
           follow the pointer value stored in this field. */
        if (*p) {
            const VarType *ut = vt_unwrap(t);
            if (ut && ut->kind == VT_POINTER) {
                void *next = NULL;
                memcpy(&next, addr, sizeof(void*)); /* reads pointer value from field */
                if (!next) return -3;
                addr = next;
                t = ut->pointee;
            }
        }
    }

    *out_addr = addr;
    *out_type = t;
    return 0;
}


/* ======================= TEMP read (stub) ======================= */

/* Read raw 64-bit scalar safely (no casting)
   TEMP: returns pseudo-random so you can validate the pipeline.
*/
int read_u64(void *addr, uint64_t *out)
{
    // if (!addr || !out) return -1;
    // memcpy(out, addr, sizeof(uint64_t));
    // return 0;
    (void)addr;
    if (!out) return -1;
    static uint64_t seed = 0x12345678abcdefULL;
    seed ^= seed << 7;
    seed ^= seed >> 9;
    seed ^= seed << 8;
    *out = seed;
    return 0;
}

/* ======================= Trigger expression evaluation ======================= */

typedef enum {
    VK_INT,
    VK_FLOAT,
    VK_STRING,
    VK_BOOL,
    VK_INVALID
} ValueKind;

typedef struct {
    ValueKind kind;
    union {
        int64_t i;
        double  f;
        const char *s; /* points into owned buffer for literals, or static for vars */
        int b;
    } v;
} Value;

static Value V_int(int64_t x)   { Value r={VK_INT};   r.v.i=x; return r; }
static Value V_float(double x) { Value r={VK_FLOAT}; r.v.f=x; return r; }
static Value V_bool(int x)     { Value r={VK_BOOL};  r.v.b=!!x; return r; }
static Value V_str(const char *s){ Value r={VK_STRING}; r.v.s=s?s:""; return r; }
static Value V_invalid(void)   { Value r={VK_INVALID}; return r; }

static int is_floatish_name(const char *n)
{
    if (!n) return 0;
    return (strcmp(n, "float") == 0 || strcmp(n, "double") == 0);
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

static int is_pointer_type(const VarType *t)
{
    t = vt_unwrap(t);
    return t && t->kind == VT_POINTER;
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

typedef struct {
    const FuncSig *sig;
    const uint64_t *raw_args;
} EvalCtx;

/* Evaluate variable: argN or argN.path.to.field
   - If member_path is set, argN is treated as pointer-to-struct base address.
   - Type decisions are heuristic for now (based on VarType name/kind).
*/
static Value eval_var(EvalCtx *C, const char *arg_ident, const char *member_path)
{
    if (!C || !C->sig || !C->raw_args) return V_invalid();

    int idx = parse_arg_index(arg_ident);
    if (idx < 0 || (size_t)idx >= C->sig->n_args) return V_invalid();

    const VarType *arg_type = C->sig->args[idx];
    uint64_t raw = C->raw_args[idx];

    /* Member access */
    if (member_path && *member_path) {
        void *addr = NULL;
        const VarType *field_type = NULL;
        int rc = resolve_member_path((void*)raw, arg_type, member_path, &addr, &field_type);
        if (rc != 0) return V_invalid();

        /* If field is char*, treat as string (demo: we don't deref yet) */
        if (is_cstring_ptr(field_type)) {
            return V_str("<cstring>");
        }

        // for the struct member random value
        uint64_t v = 0;
        if (read_u64(addr, &v) != 0) return V_invalid();

        const VarType *bt = vt_unwrap(field_type);
        if (bt && bt->kind == VT_BASE && is_floatish_name(bt->name)) {
            /* TEMP: interpret integer bits as numeric value */
            return V_float((double)(int64_t)v);
        }
        return V_int((int64_t)v);
    }

    /* Plain arg */
    if (is_cstring_ptr(arg_type)) {
        return V_str("<cstring>");
    }

    const VarType *bt = vt_unwrap(arg_type);
    if (bt && bt->kind == VT_BASE && is_floatish_name(bt->name)) {
        return V_float((double)(int64_t)raw);
    }
    return V_int((int64_t)raw);
}

/* ---------------- Tokenizer for trigger language ---------------- */

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
    TK_DOT
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

    if (c=='(') { L->i++; L->cur.kind=TK_LPAREN; return; }
    if (c==')') { L->i++; L->cur.kind=TK_RPAREN; return; }
    if (c=='<') { L->i++; L->cur.kind=TK_LT; return; }
    if (c=='>') { L->i++; L->cur.kind=TK_GT; return; }
    if (c=='.') { L->i++; L->cur.kind=TK_DOT; return; }
    if (c=='=') { L->i++; L->cur.kind=TK_ASSIGN; return; }

    /* string literal: "..." (no escapes handled yet) */
    if (c=='\"') {
        L->i++;
        size_t k=0;
        while (L->s[L->i] && L->s[L->i] != '\"') {
            if (k + 1 < sizeof(L->cur.text)) L->cur.text[k++] = L->s[L->i];
            L->i++;
        }
        if (L->s[L->i] == '\"') L->i++;
        L->cur.text[k] = 0;
        L->cur.kind = TK_STRING;
        return;
    }

    /* number/float: 10, 0x10, 3.14 */
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
            memcpy(tmp, L->s+start, n); tmp[n]=0;
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
        memcpy(tmp, L->s+start, n); tmp[n]=0;

        if (has_dot) {
            L->cur.kind = TK_FLOAT;
            L->cur.f = strtod(tmp, NULL);
        } else {
            L->cur.kind = TK_NUMBER;
            L->cur.i = (int64_t)strtoll(tmp, NULL, 10);
        }
        return;
    }

    /* identifier */
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

    /* unknown */
    L->i++;
    L->cur.kind = TK_EOF;
}

/* ---------------- Recursive descent parser ---------------- */

typedef struct {
    Lexer L;
    EvalCtx *C;
} Parser;

static Value parse_expr(Parser *P);

static void consume(Parser *P, TokKind k)
{
    if (P->L.cur.kind == k) lex_next(&P->L);
}

static Value parse_primary(Parser *P)
{
    Token t = P->L.cur;

    if (t.kind == TK_NUMBER) {
        lex_next(&P->L);
        return V_int(t.i);
    }
    if (t.kind == TK_FLOAT) {
        lex_next(&P->L);
        return V_float(t.f);
    }
    if (t.kind == TK_STRING) {
        /* store pointer to lexer-owned token buffer copy is NOT safe across lex_next;
           for this demo, we copy into a heap string. */
        char *heap = xstrdup(t.text);
        lex_next(&P->L);
        return V_str(heap);
    }

    if (t.kind == TK_IDENT) {
        char arg_ident[256];
        strncpy(arg_ident, t.text, sizeof(arg_ident));
        arg_ident[sizeof(arg_ident)-1] = 0;
        lex_next(&P->L);

        char path[512]; path[0]=0;
        while (P->L.cur.kind == TK_DOT) {
            lex_next(&P->L);
            if (P->L.cur.kind != TK_IDENT) break;
            if (path[0]) strncat(path, ".", sizeof(path)-strlen(path)-1);
            strncat(path, P->L.cur.text, sizeof(path)-strlen(path)-1);
            lex_next(&P->L);
        }

        return eval_var(P->C, arg_ident, path[0]?path:NULL);
    }

    if (t.kind == TK_LPAREN) {
        lex_next(&P->L);
        Value v = parse_expr(P);
        consume(P, TK_RPAREN);
        return v;
    }

    lex_next(&P->L);
    return V_invalid();
}

static int value_truthy(Value v)
{
    if (v.kind == VK_BOOL) return v.v.b;
    if (v.kind == VK_INT) return v.v.i != 0;
    if (v.kind == VK_FLOAT) return v.v.f != 0.0;
    if (v.kind == VK_STRING) return v.v.s && v.v.s[0] != 0;
    return 0;
}

static int cmp_values(TokKind op, Value a, Value b)
{
    /* '=' becomes '==' */
    if (op == TK_ASSIGN) op = TK_EQ;

    /* string comparisons only for == != */
    if (a.kind == VK_STRING || b.kind == VK_STRING) {
        const char *as = (a.kind == VK_STRING) ? a.v.s : "";
        const char *bs = (b.kind == VK_STRING) ? b.v.s : "";
        int eq = (strcmp(as, bs) == 0);
        if (op == TK_EQ) return eq;
        if (op == TK_NE) return !eq;
        return 0;
    }

    /* numeric: promote to float if either is float */
    if (a.kind == VK_FLOAT || b.kind == VK_FLOAT) {
        double x = (a.kind == VK_FLOAT) ? a.v.f : (double)a.v.i;
        double y = (b.kind == VK_FLOAT) ? b.v.f : (double)b.v.i;
        switch (op) {
            case TK_EQ: return x == y;
            case TK_NE: return x != y;
            case TK_LT: return x <  y;
            case TK_LE: return x <= y;
            case TK_GT: return x >  y;
            case TK_GE: return x >= y;
            default: return 0;
        }
    }

    /* ints */
    int64_t x = (a.kind == VK_INT) ? a.v.i : 0;
    int64_t y = (b.kind == VK_INT) ? b.v.i : 0;
    switch (op) {
        case TK_EQ: return x == y;
        case TK_NE: return x != y;
        case TK_LT: return x <  y;
        case TK_LE: return x <= y;
        case TK_GT: return x >  y;
        case TK_GE: return x >= y;
        default: return 0;
    }
}

static Value parse_cmp(Parser *P)
{
    Value left = parse_primary(P);

    TokKind op = P->L.cur.kind;
    if (op==TK_EQ || op==TK_NE || op==TK_LT || op==TK_LE || op==TK_GT || op==TK_GE || op==TK_ASSIGN) {
        lex_next(&P->L);
        Value right = parse_primary(P);
        return V_bool(cmp_values(op, left, right));
    }

    /* no operator => treat as truthy */
    return V_bool(value_truthy(left));
}

static Value parse_and(Parser *P)
{
    Value v = parse_cmp(P);
    while (P->L.cur.kind == TK_AND) {
        lex_next(&P->L);
        Value r = parse_cmp(P);
        v = V_bool(value_truthy(v) && value_truthy(r));
    }
    return v;
}

static Value parse_or(Parser *P)
{
    Value v = parse_and(P);
    while (P->L.cur.kind == TK_OR) {
        lex_next(&P->L);
        Value r = parse_and(P);
        v = V_bool(value_truthy(v) || value_truthy(r));
    }
    return v;
}

static Value parse_expr(Parser *P) { return parse_or(P); }

/* Evaluate one trigger string for a specific FuncSig and raw args */
static int eval_trigger_expr(const char *expr, const FuncSig *sig, const uint64_t *raw_args)
{
    if (!expr || !sig || !raw_args) return 0;

    EvalCtx C = { .sig = sig, .raw_args = raw_args };
    Parser P;
    memset(&P, 0, sizeof(P));
    P.C = &C;
    P.L.s = expr;
    P.L.i = 0;
    lex_next(&P.L);

    Value r = parse_expr(&P);
    return value_truthy(r);
}

/* ======================= Demo Pipeline ======================= */

void demo_pipeline(const char *func_name)
{
    /* 1) Build DWARF model */
    DwarfModel *model = dwarf_scan_collect_model();
    if (!model) {
        printf("[demo] failed to build DWARF model\n");
        return;
    }

    /* 2) Find function signature */
    const FuncSig *f = find_funcsig_by_name(model, func_name);
    if (!f) {
        printf("[demo] function not found: %s\n", func_name);
        dwarf_model_free(model);
        return;
    }

    printf("[demo] found function %s with %zu args\n", f->name, f->n_args);

    /* 3) Load YAML config */
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

    /* 4) Allocate fake raw args based on DWARF */
    uint64_t *raw_args = (uint64_t*)calloc(f->n_args, sizeof(uint64_t));
    if (!raw_args) {
        cfg_free(&cfg);
        dwarf_model_free(model);
        return;
    }

    void **dummy_ptrs = calloc(f->n_args, sizeof(void*));  /* keep to free later */
    for (size_t i = 0; i < f->n_args; i++) {
        if (is_pointer_type(f->args[i])) {
            dummy_ptrs[i] = calloc(1, 256);      /* dummy struct memory */
            raw_args[i] = (uint64_t)dummy_ptrs[i];
        } else {
            raw_args[i] = (uint64_t)(10 + (int)i); /* simple integer-ish values */
            if (i == 0) raw_args[i] = 10; // for demo
            if (i == 1) raw_args[i] = 19; // for demo
        }
    }

    /* 5) Evaluate trigger expressions */
    for (size_t k = 0; k < t->triggers.n; k++) {
        const char *expr = t->triggers.items[k];
        int ok = eval_trigger_expr(expr, f, raw_args);
        printf("  trigger[%zu] %s => %s\n", k, expr, ok ? "TRUE" : "FALSE");
    }

    struct timespec time;
    timer_start(&time);

    for (int i = 0; i < 1000000; i++)
        eval_trigger_expr(t->triggers.items[0], f, raw_args);

    timer_end(&time, "1M evaluations", 1000000);

    for (size_t i = 0; i < f->n_args; i++) free(dummy_ptrs[i]);
    free(dummy_ptrs);
    free(raw_args);
    cfg_free(&cfg);
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

// gcc -shared -fPIC function.c trace_config.c -o function.so -I. -L. -ldwscan -Wl,-rpath,'$ORIGIN' -lyaml
// LD_PRELOAD=./function.so ~/Codes/cpu2017/benchspec/CPU/505.mcf_r/run/run_base_refrate_ali-test1-m64.0000/mcf_r_base.ali-test1-m64