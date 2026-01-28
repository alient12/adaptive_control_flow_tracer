#ifndef TRIGGER_CHECK_H
#define TRIGGER_CHECK_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <libpatch/patch.h>          // struct patch_exec_context, patch_status, etc. :contentReference[oaicite:1]{index=1}
/* patch.h includes the x86_64 arch header internally on x86_64. :contentReference[oaicite:2]{index=2} */

// #include "libdwscan.h"               // FuncSig, VarType, VT_* from your dwscan
                                    // (and vt_unwrap() helper you already have)
#include "trigger_compiler.h"


#ifdef __cplusplus
extern "C" {
#endif

int extract_raw_args_sysv_x86_64(const struct patch_exec_context *ctx, const FuncSig *f, uint64_t *out_raw_args); 

/* ---------------- Trigger database ---------------- */
typedef struct TriggerEntry {
    size_t          index;         /* Unique global index (optional) */
    size_t          trigger_i;     /* Index within the config list */

    /* Specific trigger logic */
    char           *trigger_expr;
    CompiledTrigger compiled;      /* Owned by this entry */
    int             compiled_ok;   /* 1 if compile_trigger succeeded */
} TriggerEntry;

typedef struct GroupTriggerEntry {
    size_t      target_i;

    /* Target Metadata (Shared by all entries in this group) */
    char       *func_name;
    uint64_t    func_lowpc;
    uint64_t    func_size;

    char       *trigger_func_name;
    uint64_t    trigger_func_lowpc;
    uint64_t    trigger_func_size;

    int         recursive;
    const FuncSig *sig;            /* Common signature for the trigger function */

    /* The grouped triggers */
    TriggerEntry *entries;
    size_t        n_entries;
} GroupTriggerEntry;

typedef struct TriggerDB {
    DwarfModel        *model;
    TraceConditionCfg  cfg;

    /* Array of Groups instead of flat entries */
    GroupTriggerEntry *groups;
    size_t             n_groups;
} TriggerDB;

int triggerdb_setup(TriggerDB *db, const char *cfg_path);

#ifdef __cplusplus
}
#endif

#endif /* TRIGGER_CHECK_H */