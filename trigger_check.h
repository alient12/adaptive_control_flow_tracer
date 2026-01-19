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
    /* identity */
    size_t      index;         /* 0..n_entries-1 */
    size_t      target_i;      /* cfg target index */
    size_t      trigger_i;     /* trigger index within target */

    /* target function */
    char       *func_name;
    uint64_t    func_lowpc;
    uint64_t    func_size;

    /* trigger function (the function whose args are used in trigger expr) */
    char       *trigger_func_name;
    uint64_t    trigger_func_lowpc;
    uint64_t    trigger_func_size;

    /* config */
    int         recursive;

    /* trigger */
    char       *trigger_expr;
    const FuncSig *sig;        /* owned by DwarfModel; valid while model lives */
    CompiledTrigger compiled;  /* owned by this entry; must be freed */
    int         compiled_ok;   /* 1 if compile_trigger succeeded */
} TriggerEntry;

typedef struct TriggerDB {
    DwarfModel     *model;      /* owns FuncSig pointers */
    TraceConditionCfg cfg;      /* we keep a copy alive (so t->func strings remain valid if you want) */

    TriggerEntry   *entries;
    size_t          n_entries;
} TriggerDB;

int triggerdb_setup(TriggerDB *db, const char *cfg_path);

#ifdef __cplusplus
}
#endif

#endif /* TRIGGER_CHECK_H */