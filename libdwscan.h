#ifndef LIBDWSCAN_H
#define LIBDWSCAN_H

/*
 * Public API for libdwscan.so
 *
 * This header exposes a read-only DWARF-derived model of:
 *   - function signatures
 *   - structured argument types (including structs, unions, typedefs)
 *
 * OWNERSHIP RULES:
 *  - All VarType objects are owned by DwarfModel
 *  - Do NOT free VarType*, StructMember*, or FuncSig fields individually
 *  - Always call dwarf_model_free() when finished
 */


#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libdwarf/libdwarf.h>
#include <libdwarf/dwarf.h>

#include <elf.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================ Type Model ============================ */

typedef enum {
    VT_BASE,
    VT_POINTER,
    VT_ARRAY,
    VT_STRUCT,
    VT_UNION,
    VT_ENUM,
    VT_TYPEDEF,
    VT_QUALIFIER,
    VT_UNKNOWN
} VarKind;

typedef struct VarType VarType;

typedef struct {
    char *name;          /* member name */
    VarType *type;       /* member type tree */
    long long offset;    /* byte offset if known else -1 */
} StructMember;

struct VarType {
    VarKind kind;

    /* Human label for named types: base type name, struct name, typedef name, enum name... */
    char *name;

    /* For qualifiers */
    char *qual;          /* "const" / "volatile" (optional) */

    /* Type composition */
    VarType *pointee;    /* VT_POINTER */
    VarType *element;    /* VT_ARRAY (element type) */
    size_t array_len;    /* VT_ARRAY (0 if unknown) */

    /* Underlying type for typedef/qualifier (optional, but useful) */
    VarType *under;

    /* Struct/union members */
    StructMember *members;
    size_t n_members;

    /* DIE identity (for caching / cycle breaking) */
    Dwarf_Off die_off;
    Dwarf_Bool die_is_info;
};

/* ============================ Function Signatures ============================ */

typedef struct {
    char *name;        /* function name */
    VarType **args;    /* arg type trees */
    size_t n_args;
} FuncSig;

typedef struct {
    FuncSig *items;
    size_t len;
    size_t cap;
} FuncSigArray;

/* ============================ Cache ============================ */

typedef struct {
    Dwarf_Off off;
    Dwarf_Bool is_info;
    VarType *vt;
} TypeCacheEntry;

typedef struct {
    TypeCacheEntry *items;
    size_t len;
    size_t cap;
} TypeCache;

/* ============================ Model ============================ */

/* Opaque container that owns all VarType objects */
typedef struct {
    FuncSig *funcs;
    size_t n_funcs;

    /* Owns ALL VarType nodes through the cache list (free each exactly once). */
    TypeCache cache;
} DwarfModel;

/* ============================ Printing ============================ */

typedef struct {
    Dwarf_Off off;
    Dwarf_Bool is_info;
} TypeId;

typedef struct {
    TypeId *printed;      /* dynamic array */
    size_t printed_len;
    size_t printed_cap;
} DumpState;

/* ============================ Function Offset Table ============================ */

typedef struct {
    char *name;        /* function name (owned by table) */
    uint64_t lowpc;    /* DW_AT_low_pc as reported by DWARF */
} FuncOffEntry;

typedef struct {
    FuncOffEntry *items;
    size_t len;
    size_t cap;
} FuncOffTable;

/* ============================ Public API ============================ */

/*
 * Scan DWARF from /proc/self/exe and build a model.
 * Returns NULL on failure.
 */
DwarfModel *dwarf_scan_collect_model(void);

/* Returns NULL if not found */
const FuncSig *find_funcsig_by_name(const DwarfModel *model, const char *name);

/*
 * Free the model and ALL associated VarType objects.
 * Safe to call with NULL.
 */
void dwarf_model_free(DwarfModel *m);

/*
 * Print a function signature in compact form.
 * Example:
 *   foo(int, struct bar*, cost_t)
 */
void print_funcsig(const FuncSig *f);

/*
 * Dump struct / union members recursively in a tree format.
 * Typedefs are printed with their base type, e.g.:
 *   cost_t (= long)
 */
void dump_struct_members(const VarType *v, int indent);

/*
 * Convenience helper: find a function by name in the global model
 * and print its signature and argument structures.
 */
void print_function_by_name(const char *name);

/*
 * Build the function offset table: function name -> DW_AT_low_pc.
 *
 * Returns 0 on success, negative on failure.
 */
int dwarf_build_function_offset_table(void);

/*
 * Lookup function low_pc by name.
 *
 * Parameters:
 *   func_name: function name to look up
 *   out_lowpc: output pointer for DW_AT_low_pc value
 *
 * Returns 1 if found and out_lowpc is set, 0 if not found or on error.
 */
int dwarf_find_function_lowpc(const char *func_name, uint64_t *out_lowpc);

/*
 * Free function offset table resources.
 */
void fotab_free(FuncOffTable *t);

#ifdef __cplusplus
}
#endif

#endif /* LIBDWSCAN_H */
