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

#ifdef __cplusplus
}
#endif

#endif /* TRIGGER_CHECK_H */