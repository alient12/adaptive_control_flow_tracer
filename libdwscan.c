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

/* ------------------------------ Function offset table ------------------------------ */

/*
 * Builds a compact table: function name -> DW_AT_low_pc (address/offset).
 *
 * Notes / caveats:
 * - We record DW_AT_low_pc when present. If a subprogram has no low_pc (e.g.,
 *   only DW_AT_ranges), we currently skip it.
 * - The recorded value is whatever DWARF reports (often a link-time address or
 *   a text-section-relative offset for PIE/ET_DYN). If you need runtime address,
 *   you may need to add the load base.
 * - This is intentionally independent of DwarfModel so we don't have to touch
 *   existing structs/APIs.
 */

static FuncOffTable g_fotab = {0};

static int fotab_grow(FuncOffTable *t, size_t need)
{
    if (t->cap >= need) return 0;
    size_t nc = t->cap ? t->cap * 2 : 256;
    while (nc < need) nc *= 2;
    void *p = xrealloc(t->items, nc * sizeof(*t->items));
    if (!p) return -1;
    t->items = (FuncOffEntry*)p;
    t->cap = nc;
    return 0;
}

static int fotab_push(FuncOffTable *t, const char *name, uint64_t lowpc)
{
    if (!name || !*name) return 0;
    if (fotab_grow(t, t->len + 1) != 0) return -1;
    t->items[t->len].name = xstrdup(name);
    t->items[t->len].lowpc = lowpc;
    if (!t->items[t->len].name) return -1;
    t->len++;
    return 0;
}

void fotab_free(FuncOffTable *t)
{
    if (!t) return;
    for (size_t i = 0; i < t->len; i++) free(t->items[i].name);
    free(t->items);
    t->items = NULL;
    t->len = 0;
    t->cap = 0;
}

static int die_lowpc_u64(Dwarf_Die subp_die, uint64_t *out_lowpc, Dwarf_Error *err)
{
    if (!out_lowpc) return DW_DLV_ERROR;

    /* Prefer dwarf_lowpc_b if available in your libdwarf; fallback to attr parsing. */
#if defined(DW_DLV_OK)
    {
        Dwarf_Addr a = 0;
        int rc = dwarf_lowpc(subp_die, &a, err);
        if (rc == DW_DLV_OK) { *out_lowpc = (uint64_t)a; return DW_DLV_OK; }
    }
#endif

    Dwarf_Attribute at = 0;
    if (dwarf_attr(subp_die, DW_AT_low_pc, &at, err) != DW_DLV_OK) return DW_DLV_NO_ENTRY;

    Dwarf_Addr a = 0;
    if (dwarf_formaddr(at, &a, err) != DW_DLV_OK) return DW_DLV_ERROR;

    *out_lowpc = (uint64_t)a;
    return DW_DLV_OK;
}

static void walk_die_tree_collect_offsets(Dwarf_Die die, FuncOffTable *out, Dwarf_Error *err)
{
    if (!die) return;

    Dwarf_Half tag = 0;
    if (dwarf_tag(die, &tag, err) == DW_DLV_OK && tag == DW_TAG_subprogram) {
        char *nm = NULL;
        if (dwarf_diename(die, &nm, err) == DW_DLV_OK && nm && nm[0]) {
            uint64_t lowpc = 0;
            if (die_lowpc_u64(die, &lowpc, err) == DW_DLV_OK) {
                (void)fotab_push(out, nm, lowpc);
            }
        }
    }

    Dwarf_Die child = 0;
    if (dwarf_child(die, &child, err) == DW_DLV_OK) {
        walk_die_tree_collect_offsets(child, out, err);
    }

    Dwarf_Die sib = 0;
    int rc = dwarf_siblingof_c(die, &sib, err);
    dwarf_dealloc_die(die);
    if (rc == DW_DLV_OK) {
        walk_die_tree_collect_offsets(sib, out, err);
    }
}

/*
 * Public-ish entrypoint (no header change here): builds g_fotab once.
 * Returns 0 on success, negative on failure.
 */
int dwarf_build_function_offset_table(void)
{
    if (g_fotab.items && g_fotab.len) return 0; /* already built */

    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) return -1;

    Dwarf_Debug dbg = 0;
    Dwarf_Error err = 0;

    if (dwarf_init_b(fd, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &err) != DW_DLV_OK) {
        close(fd);
        return -1;
    }

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

        walk_die_tree_collect_offsets(cu_die, &g_fotab, &err);
    }

    dwarf_finish(dbg);
    close(fd);

    return 0;
}

/* Lookup helper (returns 1 if found, 0 otherwise). */
int dwarf_find_function_lowpc(const char *func_name, uint64_t *out_lowpc)
{
    if (!func_name || !*func_name || !out_lowpc) return 0;
    if (dwarf_build_function_offset_table() != 0) return 0;

    for (size_t i = 0; i < g_fotab.len; i++) {
        if (g_fotab.items[i].name && strcmp(g_fotab.items[i].name, func_name) == 0) {
            *out_lowpc = g_fotab.items[i].lowpc;
            return 1;
        }
    }
    return 0;
}

/* ------------------------------ ELF symbol table (augment offset table) ------------------------------ */

/*
 * Augment g_fotab using ELF symbol tables (.symtab/.dynsym). This captures
 * linker/runtime symbols which are not represented in DWARF, such as:
 *   - _start, _init, _fini
 *   - puts@plt, memcpy@plt (when present in .symtab)
 *   - many shared-library related symbols (from .dynsym)
 *
 * This does NOT change the existing DWARF collector; it simply adds extra
 * name->address mappings into the same g_fotab table.
 *
 * Limitations (by design for simplicity):
 * - 64-bit ELF only (ELFCLASS64)
 * - little-endian only (ELFDATA2LSB)
 */

static ssize_t pread_full(int fd, void *buf, size_t n, off_t off)
{
    size_t got = 0;
    while (got < n) {
        ssize_t rc = pread(fd, (char*)buf + got, n - got, off + (off_t)got);
        if (rc == 0) break;
        if (rc < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)rc;
    }
    return (ssize_t)got;
}

static int fotab_find_index(const FuncOffTable *t, const char *name)
{
    if (!t || !name) return -1;
    for (size_t i = 0; i < t->len; i++) {
        if (t->items[i].name && strcmp(t->items[i].name, name) == 0) return (int)i;
    }
    return -1;
}

static int fotab_upsert(FuncOffTable *t, const char *name, uint64_t addr)
{
    if (!t || !name || !*name) return 0;
    int idx = fotab_find_index(t, name);
    if (idx >= 0) {
        /* Keep the original DWARF lowpc if present; otherwise fill it in. */
        if (t->items[idx].lowpc == 0 && addr != 0) t->items[idx].lowpc = addr;
        return 0;
    }
    return fotab_push(t, name, addr);
}

static int sym_is_interesting(const char *nm, uint8_t st_type, const char *secname, int include_plt)
{
    if (!nm || !*nm) return 0;

    /* Most "function-like" symbols */
    if (st_type == STT_FUNC) return 1;

    /* Some toolchains mark PLT stubs as NOTYPE; allow if explicitly requested. */
    if (include_plt) {
        if (strstr(nm, "@plt") != NULL) return 1;
        if (secname && (strncmp(secname, ".plt", 4) == 0)) return 1;
    }

    /* _start sometimes shows as STT_FUNC, but keep a name-based fallback anyway. */
    if (strcmp(nm, "_start") == 0 || strcmp(nm, "_init") == 0 || strcmp(nm, "_fini") == 0) return 1;

    return 0;
}

static int elf_add_plt_stubs_from_relocs(int fd,
                                         FuncOffTable *t,
                                         int include_plt,
                                         const Elf64_Shdr *shdrs,
                                         size_t shnum,
                                         const char *shstr,
                                         size_t shstr_sz)
{
    if (!include_plt) return 0;
    if (!t || !shdrs || shnum == 0) return 0;

    /* Find a PLT section (prefer .plt.sec if present, else .plt). */
    int plt_sec = -1;
    int plt_is_sec = 0;
    for (size_t i = 0; i < shnum; i++) {
        const char *sn = NULL;
        if (shstr && shdrs[i].sh_name < shstr_sz) sn = shstr + shdrs[i].sh_name;
        if (!sn) continue;
        if (strcmp(sn, ".plt.sec") == 0) { plt_sec = (int)i; plt_is_sec = 1; break; }
        if (plt_sec < 0 && strcmp(sn, ".plt") == 0) { plt_sec = (int)i; plt_is_sec = 0; }
    }
    if (plt_sec < 0) return 0;

    uint64_t plt_base = (uint64_t)shdrs[plt_sec].sh_addr;
    size_t plt_entsz = (size_t)shdrs[plt_sec].sh_entsize;
    if (plt_entsz == 0) plt_entsz = 16; /* x86_64 default */
    size_t plt_hdr = plt_is_sec ? 0 : plt_entsz; /* .plt has a resolver entry at index 0 */

    int added = 0;

    /* Look for relocation sections typically associated with PLT. */
    for (size_t ri = 0; ri < shnum; ri++) {
        const Elf64_Shdr relh = shdrs[ri];
        const char *rn = NULL;
        if (shstr && relh.sh_name < shstr_sz) rn = shstr + relh.sh_name;
        if (!rn) continue;

        int is_plt_reloc = 0;
        if (strcmp(rn, ".rela.plt") == 0 || strcmp(rn, ".rel.plt") == 0 ||
            strcmp(rn, ".rela.plt.sec") == 0 || strcmp(rn, ".rel.plt.sec") == 0) {
            is_plt_reloc = 1;
        }
        if (!is_plt_reloc) continue;

        /* Relocations link to a symbol table (usually .dynsym). */
        if (relh.sh_link == SHN_UNDEF || relh.sh_link >= shnum) continue;
        const Elf64_Shdr symh = shdrs[relh.sh_link];
        if (symh.sh_entsize != sizeof(Elf64_Sym) || symh.sh_size < sizeof(Elf64_Sym)) continue;
        if (symh.sh_link == SHN_UNDEF || symh.sh_link >= shnum) continue;

        const Elf64_Shdr strh = shdrs[symh.sh_link];
        size_t strsz = (size_t)strh.sh_size;
        char *strtab = (char*)malloc(strsz ? strsz : 1);
        if (!strtab) continue;
        if (strsz && pread_full(fd, strtab, strsz, (off_t)strh.sh_offset) != (ssize_t)strsz) {
            free(strtab);
            continue;
        }

        size_t nsyms = (size_t)(symh.sh_size / sizeof(Elf64_Sym));
        Elf64_Sym *syms = (Elf64_Sym*)malloc(nsyms * sizeof(Elf64_Sym));
        if (!syms) {
            free(strtab);
            continue;
        }
        if (pread_full(fd, syms, nsyms * sizeof(Elf64_Sym), (off_t)symh.sh_offset) != (ssize_t)(nsyms * sizeof(Elf64_Sym))) {
            free(syms);
            free(strtab);
            continue;
        }

        /* Read relocations */
        size_t nrels = 0;
        if (relh.sh_type == SHT_RELA && relh.sh_entsize == sizeof(Elf64_Rela)) {
            nrels = (size_t)(relh.sh_size / sizeof(Elf64_Rela));
            Elf64_Rela *rels = (Elf64_Rela*)malloc(nrels * sizeof(Elf64_Rela));
            if (!rels) { free(syms); free(strtab); continue; }
            if (pread_full(fd, rels, nrels * sizeof(Elf64_Rela), (off_t)relh.sh_offset) != (ssize_t)(nrels * sizeof(Elf64_Rela))) {
                free(rels); free(syms); free(strtab); continue;
            }

            for (size_t i = 0; i < nrels; i++) {
                uint32_t symidx = (uint32_t)ELF64_R_SYM(rels[i].r_info);
                if (symidx >= nsyms) continue;
                if (syms[symidx].st_name == 0 || syms[symidx].st_name >= strsz) continue;
                const char *nm = strtab + syms[symidx].st_name;
                if (!nm || !*nm) continue;

                uint64_t stub = plt_base + (uint64_t)plt_hdr + (uint64_t)i * (uint64_t)plt_entsz;
                char buf[512];
                snprintf(buf, sizeof(buf), "%s@plt", nm);
                int before = (int)t->len;
                (void)fotab_upsert(t, buf, stub);
                if ((int)t->len > before) added++;
            }

            free(rels);
        } else if (relh.sh_type == SHT_REL && relh.sh_entsize == sizeof(Elf64_Rel)) {
            nrels = (size_t)(relh.sh_size / sizeof(Elf64_Rel));
            Elf64_Rel *rels = (Elf64_Rel*)malloc(nrels * sizeof(Elf64_Rel));
            if (!rels) { free(syms); free(strtab); continue; }
            if (pread_full(fd, rels, nrels * sizeof(Elf64_Rel), (off_t)relh.sh_offset) != (ssize_t)(nrels * sizeof(Elf64_Rel))) {
                free(rels); free(syms); free(strtab); continue;
            }

            for (size_t i = 0; i < nrels; i++) {
                uint32_t symidx = (uint32_t)ELF64_R_SYM(rels[i].r_info);
                if (symidx >= nsyms) continue;
                if (syms[symidx].st_name == 0 || syms[symidx].st_name >= strsz) continue;
                const char *nm = strtab + syms[symidx].st_name;
                if (!nm || !*nm) continue;

                uint64_t stub = plt_base + (uint64_t)plt_hdr + (uint64_t)i * (uint64_t)plt_entsz;
                char buf[512];
                snprintf(buf, sizeof(buf), "%s@plt", nm);
                int before = (int)t->len;
                (void)fotab_upsert(t, buf, stub);
                if ((int)t->len > before) added++;
            }

            free(rels);
        }

        free(syms);
        free(strtab);
    }

    return added;
}

static int elf_augment_fotab_from_fd(int fd, FuncOffTable *t, int include_plt)
{
    if (!t) return -1;

    Elf64_Ehdr eh;
    if (pread_full(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh)) return -1;

    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) return -1;
    if (eh.e_ident[EI_CLASS] != ELFCLASS64) return -1;
    if (eh.e_ident[EI_DATA] != ELFDATA2LSB) return -1;

    if (eh.e_shoff == 0 || eh.e_shentsize != sizeof(Elf64_Shdr) || eh.e_shnum == 0) return -1;

    /* Read all section headers */
    size_t shdrs_sz = (size_t)eh.e_shnum * sizeof(Elf64_Shdr);
    Elf64_Shdr *shdrs = (Elf64_Shdr*)malloc(shdrs_sz);
    if (!shdrs) return -1;

    if (pread_full(fd, shdrs, shdrs_sz, (off_t)eh.e_shoff) != (ssize_t)shdrs_sz) {
        free(shdrs);
        return -1;
    }

    /* Read section-header string table (for section names) */
    char *shstr = NULL;
    size_t shstr_sz = 0;
    if (eh.e_shstrndx != SHN_UNDEF && eh.e_shstrndx < eh.e_shnum) {
        Elf64_Shdr shstrh = shdrs[eh.e_shstrndx];
        shstr_sz = (size_t)shstrh.sh_size;
        shstr = (char*)malloc(shstr_sz ? shstr_sz : 1);
        if (shstr && shstr_sz) {
            if (pread_full(fd, shstr, shstr_sz, (off_t)shstrh.sh_offset) != (ssize_t)shstr_sz) {
                free(shstr);
                shstr = NULL;
                shstr_sz = 0;
            }
        }
    }

    int added = 0;

    /* Iterate symtab + dynsym */
    for (size_t si = 0; si < eh.e_shnum; si++) {
        Elf64_Shdr symh = shdrs[si];
        if (symh.sh_type != SHT_SYMTAB && symh.sh_type != SHT_DYNSYM) continue;
        if (symh.sh_entsize != sizeof(Elf64_Sym) || symh.sh_size < sizeof(Elf64_Sym)) continue;
        if (symh.sh_link == SHN_UNDEF || symh.sh_link >= eh.e_shnum) continue;

        /* Read the linked string table for symbol names */
        Elf64_Shdr strh = shdrs[symh.sh_link];
        size_t strsz = (size_t)strh.sh_size;
        char *strtab = (char*)malloc(strsz ? strsz : 1);
        if (!strtab) continue;
        if (strsz && pread_full(fd, strtab, strsz, (off_t)strh.sh_offset) != (ssize_t)strsz) {
            free(strtab);
            continue;
        }

        /* Read symbols */
        size_t nsyms = (size_t)(symh.sh_size / sizeof(Elf64_Sym));
        Elf64_Sym *syms = (Elf64_Sym*)malloc(nsyms * sizeof(Elf64_Sym));
        if (!syms) {
            free(strtab);
            continue;
        }
        if (pread_full(fd, syms, nsyms * sizeof(Elf64_Sym), (off_t)symh.sh_offset) != (ssize_t)(nsyms * sizeof(Elf64_Sym))) {
            free(syms);
            free(strtab);
            continue;
        }

        for (size_t i = 0; i < nsyms; i++) {
            Elf64_Sym s = syms[i];
            if (s.st_name == 0 || s.st_name >= strsz) continue;
            const char *nm = strtab + s.st_name;
            if (!nm || !*nm) continue;

            uint8_t st_type = ELF64_ST_TYPE(s.st_info);

            const char *secname = NULL;
            if (shstr && s.st_shndx != SHN_UNDEF && s.st_shndx < eh.e_shnum) {
                uint32_t noff = shdrs[s.st_shndx].sh_name;
                if (noff < shstr_sz) secname = shstr + noff;
            }

            if (!sym_is_interesting(nm, st_type, secname, include_plt)) continue;

            /* st_value is the symbol address (or 0 for undefined/imported) */
            if (s.st_value == 0) {
                /* Allow adding undefined dynsym entries if you want later, but skip for now */
                continue;
            }

            int before = (int)t->len;
            if (fotab_upsert(t, nm, (uint64_t)s.st_value) != 0) {
                /* ignore OOM errors for now */
                continue;
            }
            if ((int)t->len > before) added++;
        }

        free(syms);
        free(strtab);
    }
    /* If requested, synthesize @plt stubs from relocation sections (common case). */
    if (include_plt) {
        int plt_added = elf_add_plt_stubs_from_relocs(fd, t, include_plt, shdrs, (size_t)eh.e_shnum, shstr, shstr_sz);
        if (plt_added > 0) added += plt_added;
    }

    free(shstr);
    free(shdrs);

    return added;
}

/*
 * Public function: augment the existing DWARF-based table with ELF symbols.
 *
 * include_plt:
 *   - 0: only regular function symbols (_start/_init/_fini included)
 *   - 1: also include PLT-style stubs when found (puts@plt, memcpy@plt, ...)
 *
 * Returns: number of new entries added (>=0), or negative on error.
 */
int dwarf_update_function_offset_table_from_elf(int include_plt)
{
    /* Ensure DWARF table exists first (so ELF can "fill gaps" without overwriting). */
    if (dwarf_build_function_offset_table() != 0) {
        /* Even if DWARF failed, still try ELF; keep behavior simple */
    }

    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) return -1;

    int added = elf_augment_fotab_from_fd(fd, &g_fotab, include_plt);
    close(fd);
    return added;
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
// static DwarfModel *g_model = NULL;

// __attribute__((constructor))
// static void on_load(void)
// {
//     /* Build cache + funcs once; no printing. */
//     g_model = dwarf_scan_collect_model();

//     dwarf_build_function_offset_table();
//     dwarf_update_function_offset_table_from_elf(/*include_plt=*/1);

//     // print offset table
//     for (size_t i = 0; i < g_fotab.len; i++) {
//         printf("Function: %s -> low_pc: 0x%llx\n",
//                g_fotab.items[i].name,
//                (unsigned long long)g_fotab.items[i].lowpc);
//     }

//     print_function_by_name("price_out_impl");
// }

// __attribute__((destructor))
// static void on_unload(void)
// {
//     /* Free type/signature model */
//     dwarf_model_free(g_model);
//     g_model = NULL;

//     /* Free function offset table (if built) */
//     fotab_free(&g_fotab);
// }

// /*
//   Helper you can call from your code when you want to print a specific function.
//   Example: call this from a debug hotkey, or from your probe config stage.
// */
// void print_function_by_name(const char *name)
// {
//     if (!g_model || !name) return;
//     for (size_t i = 0; i < g_model->n_funcs; i++) {
//         if (g_model->funcs[i].name && strcmp(g_model->funcs[i].name, name) == 0) {
//             print_funcsig(&g_model->funcs[i]);
            
//             // print function arguments types and struct members
//             DumpState st;
//             if (dumpstate_init(&st, 4096) == 0) {
//                 for (size_t a = 0; a < g_model->funcs[i].n_args; a++) {
//                     dump_struct_members_state(g_model->funcs[i].args[a], 2, &st);
//                 }
//                 dumpstate_free(&st);
//             }
//             return;
//         }
//     }
// }


// gcc -shared -fPIC libdwscan.c -o libdwscan.so -ldwarf -lz
// LD_PRELOAD=./libdwscan.so ../new-libpatch/example-program
// LD_PRELOAD=./libdwscan.so ~/Codes/cpu2017/benchspec/CPU/505.mcf_r/run/run_base_refrate_ali-test1-m64.0000/mcf_r_base.ali-test1-m64
