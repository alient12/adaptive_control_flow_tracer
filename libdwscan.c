/*
  DWARF scan -> array of function signatures with structured argument types.
  - Uses libdwarf APIs per prevanders docs style (dwarf_init_b, dwarf_next_cu_header_e,
    dwarf_child, dwarf_siblingof_c, dwarf_dietype_offset, dwarf_offdie_b, dwarf_finish).
  - Builds a VarType tree for each argument type.
  - Expands struct/union members recursively.
  - Uses a DIE-based cache to avoid infinite recursion on self-referential types.

  Build (shared object for LD_PRELOAD):
    gcc -shared -fPIC libdwscan.c -o libdwscan.so \
      -I/usr/local/include -L/usr/local/lib -Wl,-rpath,/usr/local/lib \
      -ldwarf -lz

  Usage idea:
    - In your preloaded .so, call dwarf_scan_collect_model() once (constructor or on-demand)
      to get a DwarfModel*.
    - Then you can print any function signature on demand.

  Note:
    - Member offsets: DW_AT_data_member_location can be an expression; here we only
      handle the common constant udata case (best-effort).
    - Typedefs: stored as VT_TYPEDEF with underlying type in .under (you can choose how
      to print).
*/

#define _GNU_SOURCE

#include "libdwscan.h"

/* ------------------------------ helpers ------------------------------ */

static char *xstrdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = (char*)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n);
    return q;
}

/* ------------------------------ VarType model ------------------------------ */

static VarType *vt_new(void) {
    return (VarType*)calloc(1, sizeof(VarType));
}

/* ------------------------------ Cache (DIE -> VarType*) ------------------------------ */

static VarType *cache_lookup(TypeCache *c, Dwarf_Off off, Dwarf_Bool is_info) {
    for (size_t i = 0; i < c->len; i++) {
        if (c->items[i].off == off && c->items[i].is_info == is_info)
            return c->items[i].vt;
    }
    return NULL;
}

static int cache_insert(TypeCache *c, Dwarf_Off off, Dwarf_Bool is_info, VarType *vt) {
    if (c->len == c->cap) {
        size_t nc = c->cap ? c->cap * 2 : 256;
        void *p = xrealloc(c->items, nc * sizeof(*c->items));
        if (!p) return -1;
        c->items = (TypeCacheEntry*)p;
        c->cap = nc;
    }
    c->items[c->len++] = (TypeCacheEntry){off, is_info, vt};
    return 0;
}

/* ------------------------------ Function signature model ------------------------------ */

static int funcs_grow(FuncSigArray *a, size_t need) {
    if (a->cap >= need) return 0;
    size_t nc = a->cap ? a->cap * 2 : 128;
    while (nc < need) nc *= 2;
    void *p = xrealloc(a->items, nc * sizeof(*a->items));
    if (!p) return -1;
    a->items = (FuncSig*)p;
    a->cap = nc;
    return 0;
}

static int funcs_push(FuncSigArray *a, FuncSig *f) {
    if (funcs_grow(a, a->len + 1) != 0) return -1;
    a->items[a->len++] = *f;
    memset(f, 0, sizeof(*f));
    return 0;
}

/* ------------------------------ DWARF utilities ------------------------------ */

static int get_type_ref(Dwarf_Die die_with_DW_AT_type,
                        Dwarf_Off *out_off,
                        Dwarf_Bool *out_is_info,
                        Dwarf_Error *err)
{
    /* Returns offset and whether it refers to .debug_info or .debug_types */
    return dwarf_dietype_offset(die_with_DW_AT_type, out_off, out_is_info, err);
}

static int off_to_die(Dwarf_Debug dbg,
                      Dwarf_Off off,
                      Dwarf_Bool is_info,
                      Dwarf_Die *out_die,
                      Dwarf_Error *err)
{
    return dwarf_offdie_b(dbg, off, is_info, out_die, err);
}

static char *die_name_or(Dwarf_Die die, Dwarf_Error *err, const char *fallback) {
    char *n = NULL;
    if (dwarf_diename(die, &n, err) == DW_DLV_OK && n && n[0]) return xstrdup(n);
    return xstrdup(fallback);
}

/* Best-effort: DW_AT_data_member_location can be an expression; handle constant udata only. */
static long long member_offset_bytes(Dwarf_Die member_die, Dwarf_Error *err) {
    Dwarf_Attribute a = 0;
    if (dwarf_attr(member_die, DW_AT_data_member_location, &a, err) != DW_DLV_OK)
        return -1;

    Dwarf_Unsigned u = 0;
    if (dwarf_formudata(a, &u, err) == DW_DLV_OK)
        return (long long)u;

    return -1;
}

/* ------------------------------ VarType builder ------------------------------ */

static VarType *build_type_from_die(Dwarf_Debug dbg,
                                    Dwarf_Die type_die,
                                    Dwarf_Off die_off,
                                    Dwarf_Bool die_is_info,
                                    TypeCache *cache,
                                    int depth);

static VarType *follow_underlying_type(Dwarf_Debug dbg,
                                       Dwarf_Die die_with_DW_AT_type,
                                       TypeCache *cache,
                                       int depth)
{
    Dwarf_Error err = 0;
    Dwarf_Off off = 0;
    Dwarf_Bool is_info = 0;

    if (get_type_ref(die_with_DW_AT_type, &off, &is_info, &err) != DW_DLV_OK)
        return NULL;

    Dwarf_Die inner = 0;
    if (off_to_die(dbg, off, is_info, &inner, &err) != DW_DLV_OK)
        return NULL;

    VarType *vt = build_type_from_die(dbg, inner, off, is_info, cache, depth + 1);
    dwarf_dealloc_die(inner);
    return vt;
}

static VarType *build_struct_members(Dwarf_Debug dbg,
                                     Dwarf_Die struct_die,
                                     VarType *out_vt,
                                     TypeCache *cache,
                                     int depth)
{
    Dwarf_Error err = 0;

    Dwarf_Die child = 0;
    if (dwarf_child(struct_die, &child, &err) != DW_DLV_OK)
        return out_vt;

    Dwarf_Die cur = child;
    for (;;) {
        Dwarf_Half tag = 0;
        if (dwarf_tag(cur, &tag, &err) == DW_DLV_OK && tag == DW_TAG_member) {
            StructMember *nm = (StructMember*)xrealloc(out_vt->members,
                (out_vt->n_members + 1) * sizeof(*out_vt->members));
            if (nm) {
                out_vt->members = nm;
                StructMember *m = &out_vt->members[out_vt->n_members++];
                memset(m, 0, sizeof(*m));

                m->name = die_name_or(cur, &err, "<anon>");
                m->offset = member_offset_bytes(cur, &err);

                /* member type */
                Dwarf_Off moff = 0;
                Dwarf_Bool mis = 0;
                if (get_type_ref(cur, &moff, &mis, &err) == DW_DLV_OK) {
                    Dwarf_Die mdie = 0;
                    if (off_to_die(dbg, moff, mis, &mdie, &err) == DW_DLV_OK) {
                        m->type = build_type_from_die(dbg, mdie, moff, mis, cache, depth + 1);
                        dwarf_dealloc_die(mdie);
                    }
                }
                if (!m->type) {
                    m->type = vt_new();
                    if (m->type) {
                        m->type->kind = VT_UNKNOWN;
                        m->type->name = xstrdup("<?>");
                    }
                }
            }
        }

        Dwarf_Die sib = 0;
        int rc = dwarf_siblingof_c(cur, &sib, &err);
        dwarf_dealloc_die(cur);
        if (rc != DW_DLV_OK) break;
        cur = sib;
    }

    return out_vt;
}

static VarType *build_type_from_die(Dwarf_Debug dbg,
                                    Dwarf_Die type_die,
                                    Dwarf_Off die_off,
                                    Dwarf_Bool die_is_info,
                                    TypeCache *cache,
                                    int depth)
{
    if (depth > 64) {
        VarType *v = vt_new();
        if (v) { v->kind = VT_UNKNOWN; v->name = xstrdup("<depth>"); }
        return v;
    }

    /* cycle breaker */
    VarType *cached = cache_lookup(cache, die_off, die_is_info);
    if (cached) return cached;

    Dwarf_Error err = 0;
    Dwarf_Half tag = 0;
    if (dwarf_tag(type_die, &tag, &err) != DW_DLV_OK)
        tag = 0;

    /* placeholder inserted immediately (important for self-referential types) */
    VarType *v = vt_new();
    if (!v) return NULL;
    v->die_off = die_off;
    v->die_is_info = die_is_info;
    if (cache_insert(cache, die_off, die_is_info, v) != 0) {
        free(v);
        return NULL;
    }

    switch (tag) {
        case DW_TAG_base_type:
            v->kind = VT_BASE;
            v->name = die_name_or(type_die, &err, "base");
            break;

        case DW_TAG_pointer_type:
            v->kind = VT_POINTER;
            v->pointee = follow_underlying_type(dbg, type_die, cache, depth);
            if (!v->pointee) {
                v->pointee = vt_new();
                if (v->pointee) { v->pointee->kind = VT_BASE; v->pointee->name = xstrdup("void"); }
            }
            break;

        case DW_TAG_const_type:
        case DW_TAG_volatile_type:
            v->kind = VT_QUALIFIER;
            v->qual = xstrdup(tag == DW_TAG_const_type ? "const" : "volatile");
            v->under = follow_underlying_type(dbg, type_die, cache, depth);
            break;

        case DW_TAG_typedef:
            v->kind = VT_TYPEDEF;
            v->name = die_name_or(type_die, &err, "typedef");
            v->under = follow_underlying_type(dbg, type_die, cache, depth);
            break;

        case DW_TAG_structure_type:
            v->kind = VT_STRUCT;
            v->name = die_name_or(type_die, &err, "<anon>");
            build_struct_members(dbg, type_die, v, cache, depth);
            break;

        case DW_TAG_union_type:
            v->kind = VT_UNION;
            v->name = die_name_or(type_die, &err, "<anon>");
            build_struct_members(dbg, type_die, v, cache, depth);
            break;

        case DW_TAG_enumeration_type:
            v->kind = VT_ENUM;
            v->name = die_name_or(type_die, &err, "<anon>");
            break;

        default:
            v->kind = VT_UNKNOWN;
            v->name = xstrdup("<?>");
            break;
    }

    return v;
}

/* ------------------------------ Collect functions ------------------------------ */

static int collect_one_subprogram(Dwarf_Debug dbg,
                                  Dwarf_Die subp_die,
                                  FuncSigArray *out,
                                  TypeCache *cache,
                                  Dwarf_Error *err)
{
    FuncSig f;
    memset(&f, 0, sizeof(f));

    f.name = die_name_or(subp_die, err, "<anon>");
    if (!f.name) return -1;

    size_t cap = 0;

    Dwarf_Die child = 0;
    if (dwarf_child(subp_die, &child, err) == DW_DLV_OK) {
        Dwarf_Die cur = child;
        for (;;) {
            Dwarf_Half tag = 0;
            dwarf_tag(cur, &tag, err);

            if (tag == DW_TAG_formal_parameter) {
                if (f.n_args + 1 > cap) {
                    size_t nc = cap ? cap * 2 : 4;
                    void *p = xrealloc(f.args, nc * sizeof(*f.args));
                    if (!p) {
                        dwarf_dealloc_die(cur);
                        goto oom;
                    }
                    f.args = (VarType**)p;
                    cap = nc;
                }

                VarType *vt = NULL;
                Dwarf_Off toff = 0;
                Dwarf_Bool tis = 0;

                if (get_type_ref(cur, &toff, &tis, err) == DW_DLV_OK) {
                    Dwarf_Die tdie = 0;
                    if (off_to_die(dbg, toff, tis, &tdie, err) == DW_DLV_OK) {
                        vt = build_type_from_die(dbg, tdie, toff, tis, cache, 0);
                        dwarf_dealloc_die(tdie);
                    }
                }

                if (!vt) {
                    vt = vt_new();
                    if (vt) { vt->kind = VT_UNKNOWN; vt->name = xstrdup("<?>"); }
                }

                f.args[f.n_args++] = vt;
            }

            Dwarf_Die sib = 0;
            int rc = dwarf_siblingof_c(cur, &sib, err);
            dwarf_dealloc_die(cur);
            if (rc != DW_DLV_OK) break;
            cur = sib;
        }
    }

    if (funcs_push(out, &f) != 0) goto oom;
    return 0;

oom:
    free(f.name);
    free(f.args);
    return -1;
}

static void walk_die_tree_collect(Dwarf_Debug dbg,
                                  Dwarf_Die die,
                                  FuncSigArray *out,
                                  TypeCache *cache,
                                  Dwarf_Error *err)
{
    if (!die) return;

    Dwarf_Half tag = 0;
    if (dwarf_tag(die, &tag, err) == DW_DLV_OK) {
        if (tag == DW_TAG_subprogram) {
            (void)collect_one_subprogram(dbg, die, out, cache, err);
        }
    }

    Dwarf_Die child = 0;
    if (dwarf_child(die, &child, err) == DW_DLV_OK) {
        walk_die_tree_collect(dbg, child, out, cache, err);
    }

    Dwarf_Die sib = 0;
    int rc = dwarf_siblingof_c(die, &sib, err);
    dwarf_dealloc_die(die);
    if (rc == DW_DLV_OK) {
        walk_die_tree_collect(dbg, sib, out, cache, err);
    }
}

/* ------------------------------ Public: scan -> model ------------------------------ */

DwarfModel *dwarf_scan_collect_model(void)
{
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) return NULL;

    Dwarf_Debug dbg = 0;
    Dwarf_Error err = 0;

    if (dwarf_init_b(fd, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &err) != DW_DLV_OK) {
        close(fd);
        return NULL;
    }

    DwarfModel *m = (DwarfModel*)calloc(1, sizeof(*m));
    if (!m) {
        dwarf_finish(dbg);
        close(fd);
        return NULL;
    }

    FuncSigArray funcs;
    memset(&funcs, 0, sizeof(funcs));

    for (;;) {
        Dwarf_Die cu_die = 0;
        Dwarf_Unsigned cu_header_length = 0;
        Dwarf_Half version_stamp = 0;
        Dwarf_Off abbrev_offset = 0;
        Dwarf_Half address_size = 0;
        Dwarf_Half length_size = 0;
        Dwarf_Half extension_size = 0;
        Dwarf_Sig8 type_signature;
        Dwarf_Unsigned typeoffset = 0;
        Dwarf_Unsigned next_cu_header_offset = 0;
        Dwarf_Half header_cu_type = 0;

        int rc = dwarf_next_cu_header_e(
            dbg,
            /*dw_is_info=*/1,
            &cu_die,
            &cu_header_length,
            &version_stamp,
            &abbrev_offset,
            &address_size,
            &length_size,
            &extension_size,
            &type_signature,
            &typeoffset,
            &next_cu_header_offset,
            &header_cu_type,
            &err);

        if (rc == DW_DLV_NO_ENTRY) break;
        if (rc != DW_DLV_OK) break;

        walk_die_tree_collect(dbg, cu_die, &funcs, &m->cache, &err);
    }

    dwarf_finish(dbg);
    close(fd);

    m->funcs = funcs.items;
    m->n_funcs = funcs.len;
    return m;
}

const FuncSig *find_funcsig_by_name(const DwarfModel *model, const char *name)
{
    if (!model || !name || !*name) return NULL;

    for (size_t i = 0; i < model->n_funcs; i++) {
        const FuncSig *f = &model->funcs[i];
        if (f->name && strcmp(f->name, name) == 0)
            return f;
    }
    return NULL;
}

/* ------------------------------ Printing ------------------------------ */

static const VarType *unwrap_typedef_qual(const VarType *v)
{
    const VarType *cur = v;
    for (int i = 0; cur && i < 32; i++) {
        if (cur->kind == VT_TYPEDEF || cur->kind == VT_QUALIFIER) cur = cur->under;
        else break;
    }
    return cur;
}

/* Compact printer (good for function signatures): keeps typedef names as-is. */
static void print_vartype(const VarType *v, int depth)
{
    if (!v) { printf("<?>"); return; }
    if (depth > 16) { printf("<depth>"); return; }

    switch (v->kind) {
        case VT_BASE:
            printf("%s", v->name ? v->name : "base");
            break;

        case VT_POINTER:
            print_vartype(v->pointee, depth + 1);
            printf("*");
            break;

        case VT_QUALIFIER:
            if (v->qual) printf("%s ", v->qual);
            if (v->under) print_vartype(v->under, depth + 1);
            else printf("<?>");
            break;

        case VT_TYPEDEF:
            printf("%s", v->name ? v->name : "typedef");
            break;

        case VT_STRUCT:
            printf("struct %s", v->name ? v->name : "<anon>");
            break;

        case VT_UNION:
            printf("union %s", v->name ? v->name : "<anon>");
            break;

        case VT_ENUM:
            printf("enum %s", v->name ? v->name : "<anon>");
            break;

        case VT_ARRAY:
            print_vartype(v->element, depth + 1);
            printf("[%zu]", v->array_len);
            break;

        default:
            printf("<?>");
            break;
    }
}

/* Verbose printer (good for dump): shows typedef base/underlying type like a definition. */
static void print_vartype_verbose(const VarType *v, int depth)
{
    if (!v) { printf("<?>"); return; }
    if (depth > 16) { printf("<depth>"); return; }

    switch (v->kind) {
        case VT_TYPEDEF: {
            /* Show typedef name AND its ultimate underlying base-ish type. */
            printf("%s", v->name ? v->name : "typedef");
            const VarType *u = unwrap_typedef_qual(v->under);
            if (u) {
                printf(" (= ");
                /* Use compact printer for the underlying so pointers/struct names stay short */
                print_vartype(u, depth + 1);
                printf(")");
            }
            break;
        }

        case VT_POINTER:
            /* For pointers, keep declared pointee compact; typedef expansion happens at VT_TYPEDEF */
            print_vartype_verbose(v->pointee, depth + 1);
            printf("*");
            break;

        case VT_QUALIFIER:
            if (v->qual) printf("%s ", v->qual);
            if (v->under) print_vartype_verbose(v->under, depth + 1);
            else printf("<?>");
            break;

        default:
            /* Fall back to compact for everything else */
            print_vartype(v, depth);
            break;
    }
}

void print_funcsig(const FuncSig *f)
{
    if (!f) return;
    printf("%s(", f->name ? f->name : "<anon>");
    for (size_t i = 0; i < f->n_args; i++) {
        if (i) printf(", ");
        print_vartype(f->args[i], 0);
    }
    printf(")\n");
}

/* Optional: dump struct/union members in a clean tree layout (handles nesting)
   Example output:

     struct Foo
     ├─ .a @0: int
     └─ .b @8: struct Bar*
        ├─ .x @0: double
        └─ .y @8: struct Baz
           └─ .z @0: int

   Notes:
   - We *print* the declared member type (including typedef/pointer/qualifiers).
   - We *expand* into nested members if the underlying pointee/typedef/qual chain
     leads to a struct/union with available member DIEs.
   - Cycle-safe: detects self-references along the current path.
*/

static int typeid_eq(TypeId a, TypeId b) { return a.off == b.off && a.is_info == b.is_info; }

static const VarType *unwrap_for_expand(const VarType *v)
{
    /* Peel typedef/qualifiers; if pointer, expand pointee (so Node* expands Node). */
    const VarType *cur = v;
    for (int i = 0; cur && i < 16; i++) {
        if (cur->kind == VT_TYPEDEF || cur->kind == VT_QUALIFIER) { cur = cur->under; continue; }
        if (cur->kind == VT_POINTER) { cur = cur->pointee; continue; }
        break;
    }
    /* Peel again in case pointee is typedef/qual */
    for (int i = 0; cur && i < 16; i++) {
        if (cur->kind == VT_TYPEDEF || cur->kind == VT_QUALIFIER) cur = cur->under;
        else break;
    }
    return cur;
}

static int has_members(const VarType *v)
{
    if (!v) return 0;
    if (v->kind != VT_STRUCT && v->kind != VT_UNION) return 0;
    return v->n_members > 0 && v->members != NULL;
}

static int set_contains(const TypeId *set, size_t n, TypeId id)
{
    for (size_t i = 0; i < n; i++) {
        if (typeid_eq(set[i], id)) return 1;
    }
    return 0;
}

static int set_add(TypeId *set, size_t *n, size_t cap, TypeId id)
{
    if (*n >= cap) return 0;
    set[(*n)++] = id;
    return 1;
}

static void dump_one_member_line(const StructMember *m,
                                 int is_last,
                                 const char *prefix)
{
    const char *branch = is_last ? "└─ " : "├─ ";
    printf("%s%s.%s @%lld: ",
           prefix, branch,
           m->name ? m->name : "<anon>",
           m->offset);

    /* In dumps, show typedefs with their base (e.g., cost_t (= long)). */
    print_vartype_verbose(m->type, 0);
    putchar('\n');
}

static void dump_struct_members_impl(const VarType *declared_struct,
                                     const char *prefix,
                                     const TypeId *path,
                                     size_t path_len,
                                     TypeId *printed,
                                     size_t *printed_len)
{
    if (!declared_struct) return;

    TypeId me = (TypeId){ declared_struct->die_off, declared_struct->die_is_info };

    /* If already printed once, show a short note and do not expand again */
    if (set_contains(printed, *printed_len, me)) {
        printf("%s", prefix);
        if (declared_struct->kind == VT_STRUCT) printf("struct %s (see above)\n", declared_struct->name ? declared_struct->name : "<anon>");
        else if (declared_struct->kind == VT_UNION) printf("union %s (see above)\n", declared_struct->name ? declared_struct->name : "<anon>");
        else printf("<?> (see above)\n");
        return;
    }

    /* Mark printed globally for this dump call (no per-branch copies!) */
    (void)set_add(printed, printed_len, 1024, me);

    /* Print header */
    printf("%s", prefix);
    if (declared_struct->kind == VT_STRUCT) printf("struct %s\n", declared_struct->name ? declared_struct->name : "<anon>");
    else if (declared_struct->kind == VT_UNION) printf("union %s\n", declared_struct->name ? declared_struct->name : "<anon>");
    else printf("<?>\n");

    for (size_t i = 0; i < declared_struct->n_members; i++) {
        const StructMember *m = &declared_struct->members[i];
        int is_last = (i + 1 == declared_struct->n_members);
        dump_one_member_line(m, is_last, prefix);

        const VarType *exp = unwrap_for_expand(m->type);
        if (!has_members(exp)) continue;

        TypeId id = (TypeId){ exp->die_off, exp->die_is_info };
        if (set_contains(path, path_len, id)) {
            const char *cont = is_last ? "   " : "│  ";
            printf("%s%s%s<cycle>\n", prefix, cont, "└─ ");
            continue;
        }

        char next_prefix[1024];
        const char *cont = is_last ? "   " : "│  ";
        snprintf(next_prefix, sizeof(next_prefix), "%s%s", prefix, cont);

        TypeId next_path[64];
        size_t next_path_len = path_len;
        memcpy(next_path, path, path_len * sizeof(TypeId));
        (void)set_add(next_path, &next_path_len, 64, id);

        dump_struct_members_impl(exp, next_prefix, next_path, next_path_len, printed, printed_len);
    }
}


static int dumpstate_init(DumpState *st, size_t cap)
{
    st->printed = (TypeId*)calloc(cap, sizeof(TypeId));
    if (!st->printed) return -1;
    st->printed_len = 0;
    st->printed_cap = cap;
    return 0;
}

static void dumpstate_free(DumpState *st)
{
    if (!st) return;
    free(st->printed);
    st->printed = NULL;
    st->printed_len = 0;
    st->printed_cap = 0;
}

/* Dump struct/union members, but deduplicate type definitions across multiple calls
   by reusing the same DumpState (useful when dumping multiple args of one function).
*/
void dump_struct_members_state(const VarType *v, int indent, DumpState *st)
{
    (void)indent;
    if (!v || !st || !st->printed || st->printed_cap == 0) return;

    const VarType *exp = unwrap_for_expand(v);
    if (!has_members(exp)) return;

    TypeId path[64];
    size_t path_len = 0;
    (void)set_add(path, &path_len, 64, (TypeId){ exp->die_off, exp->die_is_info });

    dump_struct_members_impl(exp, "", path, path_len, st->printed, &st->printed_len);
}

/* Backwards-compatible wrapper: dedup only within this single call */
void dump_struct_members(const VarType *v, int indent)
{
    DumpState st;
    if (dumpstate_init(&st, 4096) != 0) return;
    dump_struct_members_state(v, indent, &st);
    dumpstate_free(&st);
}

/* ------------------------------ Freeing ------------------------------ */

static void free_vartype_shallow(VarType *v)
{
    if (!v) return;
    free(v->name);
    free(v->qual);

    if (v->members) {
        for (size_t i = 0; i < v->n_members; i++) {
            free(v->members[i].name);
            /* member->type is owned by cache; don't free here */
        }
        free(v->members);
    }

    /* pointee/under/element are owned by cache as well */
    free(v);
}

void dwarf_model_free(DwarfModel *m)
{
    if (!m) return;

    /* Free function signatures (names + arg pointer arrays only). */
    if (m->funcs) {
        for (size_t i = 0; i < m->n_funcs; i++) {
            free(m->funcs[i].name);
            free(m->funcs[i].args);
        }
        free(m->funcs);
    }

    /* Free each VarType exactly once using the cache */
    for (size_t i = 0; i < m->cache.len; i++) {
        free_vartype_shallow(m->cache.items[i].vt);
    }
    free(m->cache.items);

    free(m);
}

/* ------------------------------ Example usage hooks ------------------------------ */

/*
  If you want: keep model global, but DO NOT print automatically.
  You can call print_funcsig(&model->funcs[i]) wherever you want.
*/
static DwarfModel *g_model = NULL;

__attribute__((constructor))
static void on_load(void)
{
    /* Build cache + funcs once; no printing. */
    g_model = dwarf_scan_collect_model();
}

__attribute__((destructor))
static void on_unload(void)
{
    dwarf_model_free(g_model);
    g_model = NULL;
}

/*
  Helper you can call from your code when you want to print a specific function.
  Example: call this from a debug hotkey, or from your probe config stage.
*/
void print_function_by_name(const char *name)
{
    if (!g_model || !name) return;
    for (size_t i = 0; i < g_model->n_funcs; i++) {
        if (g_model->funcs[i].name && strcmp(g_model->funcs[i].name, name) == 0) {
            print_funcsig(&g_model->funcs[i]);
            
            // print function arguments types and struct members
            DumpState st;
            if (dumpstate_init(&st, 4096) == 0) {
                for (size_t a = 0; a < g_model->funcs[i].n_args; a++) {
                    dump_struct_members_state(g_model->funcs[i].args[a], 2, &st);
                }
                dumpstate_free(&st);
            }
            return;
        }
    }
}


// gcc -shared -fPIC libdwscan.c -o libdwscan.so -ldwarf -lz
// LD_PRELOAD=./libdwscan.so ../new-libpatch/example-program
// LD_PRELOAD=./libdwscan.so ~/Codes/cpu2017/benchspec/CPU/505.mcf_r/run/run_base_refrate_ali-test1-m64.0000/mcf_r_base.ali-test1-m64
