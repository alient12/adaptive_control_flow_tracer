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

#include "trace_config.h"

/* ======================= Shared model (from libdwscan) ======================= */
#include "libdwscan.h"

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

/* ======================= Trigger expression evaluation (compiled once) ======================= */

/*
  Hot path goal:
    - Parse each trigger string ONCE (after loading YAML)
    - Precompile variable references (argN.member.member) into offset/deref steps
    - Evaluate compiled AST repeatedly with new raw_args (no lex/parse at runtime)

  This is already a big win vs parsing every call. Later we can switch to bytecode.
*/

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
        const char *s;
        int b;
    } v;
} Value;

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

/* ---------- Precompiled variable reference ---------- */

typedef enum {
    STEP_ADD_OFFSET = 1,
    STEP_DEREF_PTR  = 2
} StepKind;

typedef struct {
    StepKind kind;
    uint32_t offset; /* only for ADD_OFFSET */
} AccessStep;

typedef struct {
    int arg_index;            /* argN */
    ValueKind hint_kind;      /* best-effort: int/float/string */
    const VarType *final_type;/* best-effort */
    AccessStep *steps;
    size_t n_steps;
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

static VarRef varref_from_tokens(const FuncSig *sig, const char *arg_ident, const char *member_path)
{
    VarRef r;
    memset(&r, 0, sizeof(r));
    r.arg_index = -1;
    r.hint_kind = VK_INT;
    r.final_type = NULL;

    int idx = parse_arg_index(arg_ident);
    if (idx < 0 || !sig || (size_t)idx >= sig->n_args) return r;
    r.arg_index = idx;

    const VarType *arg_type = sig->args[idx];

    if (!member_path || !*member_path) {
        if (is_cstring_ptr(arg_type)) r.hint_kind = VK_STRING;
        else {
            const VarType *bt = vt_unwrap(arg_type);
            if (bt && bt->kind == VT_BASE && is_floatish_name(bt->name)) r.hint_kind = VK_FLOAT;
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
        else r.hint_kind = VK_INT;
    }

    return r;
}

static Value eval_varref(const VarRef *v, const FuncSig *sig, const uint64_t *raw_args)
{
    (void)sig;
    if (!v || !raw_args || v->arg_index < 0) return V_invalid();

    uint64_t raw = raw_args[v->arg_index];

    if (v->hint_kind == VK_STRING) {
        return V_str("<cstring>");
    }

    if (!v->steps || v->n_steps == 0) {
        if (v->hint_kind == VK_FLOAT) return V_float((double)(int64_t)raw);
        return V_int((int64_t)raw);
    }

    uintptr_t addr = (uintptr_t)raw;

    for (size_t i = 0; i < v->n_steps; i++) {
        const AccessStep *st = &v->steps[i];
        if (st->kind == STEP_ADD_OFFSET) {
            addr += (uintptr_t)st->offset;
        } else if (st->kind == STEP_DEREF_PTR) {
            void *next = NULL;
            memcpy(&next, (void*)addr, sizeof(void*));
            addr = (uintptr_t)next;
            if (!addr) return V_invalid();
        }
    }

    uint64_t vv = 0;
    if (read_u64((void*)addr, &vv) != 0) return V_invalid();

    if (v->hint_kind == VK_FLOAT) return V_float((double)(int64_t)vv);
    return V_int((int64_t)vv);
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

typedef struct {
    Node *root;
    char *expr_owned;
} CompiledTrigger;

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

static void compiled_trigger_free(CompiledTrigger *t)
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
    Token t = P->L.cur;

    if (t.kind == TK_NUMBER) {
        Node *n = node_new(N_CONST);
        if (!n) return NULL;
        n->u.cval = V_int(t.i);
        lex_next(&P->L);
        return n;
    }

    if (t.kind == TK_FLOAT) {
        Node *n = node_new(N_CONST);
        if (!n) return NULL;
        n->u.cval = V_float(t.f);
        lex_next(&P->L);
        return n;
    }

    if (t.kind == TK_STRING) {
        Node *n = node_new(N_CONST);
        if (!n) return NULL;
        n->u.cval = V_str(xstrdup(t.text));
        lex_next(&P->L);
        return n;
    }

    if (t.kind == TK_IDENT) {
        char arg_ident[256];
        strncpy(arg_ident, t.text, sizeof(arg_ident));
        arg_ident[sizeof(arg_ident)-1] = 0;
        lex_next(&P->L);

        char path[512]; path[0] = 0;
        while (P->L.cur.kind == TK_DOT) {
            lex_next(&P->L);
            if (P->L.cur.kind != TK_IDENT) break;
            if (path[0]) strncat(path, ".", sizeof(path)-strlen(path)-1);
            strncat(path, P->L.cur.text, sizeof(path)-strlen(path)-1);
            lex_next(&P->L);
        }

        Node *n = node_new(N_VAR);
        if (!n) return NULL;
        n->u.vref = varref_from_tokens(P->sig, arg_ident, path[0] ? path : NULL);
        return n;
    }

    if (t.kind == TK_LPAREN) {
        lex_next(&P->L);
        Node *e = parse_ast_expr(P);
        cconsume(P, TK_RPAREN);
        return e;
    }

    lex_next(&P->L);
    return NULL;
}

static Node *parse_ast_cmp(CParser *P)
{
    Node *left = parse_ast_primary(P);
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

static int compile_trigger(CompiledTrigger *out, const char *expr, const FuncSig *sig)
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

    if (a.kind == VK_FLOAT || b.kind == VK_FLOAT) {
        double x = (a.kind == VK_FLOAT) ? a.v.f : (double)a.v.i;
        double y = (b.kind == VK_FLOAT) ? b.v.f : (double)b.v.i;
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

static int eval_compiled_trigger(const CompiledTrigger *t, const FuncSig *sig, const uint64_t *raw_args)
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


// gcc -shared -fPIC trigger_compiler.c trace_config.c -o trigger_compiler.so -I. -L. -ldwscan -Wl,-rpath,'$ORIGIN' -lyaml
// LD_PRELOAD=./trigger_compiler.so ~/Codes/cpu2017/benchspec/CPU/505.mcf_r/run/run_base_refrate_ali-test1-m64.0000/mcf_r_base.ali-test1-m64