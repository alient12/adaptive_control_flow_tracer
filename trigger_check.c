#include "trigger_check.h"

/* ---- helpers (same style as your code) ---- */

static const VarType *vt_unwrap_local(const VarType *v) {
    while (v && (v->kind == VT_TYPEDEF || v->kind == VT_QUALIFIER)) v = v->under;
    return v;
}

static int vartype_is_float_or_double(const VarType *t) {
    t = vt_unwrap_local(t);
    if (!t) return 0;
    if (t->kind == VT_BASE && t->name) {
        return (strcmp(t->name, "float") == 0 || strcmp(t->name, "double") == 0);
    }
    return 0;
}

static int vartype_is_float(const VarType *t) {
    t = vt_unwrap_local(t);
    return (t && t->kind == VT_BASE && t->name && strcmp(t->name, "float") == 0);
}

static int vartype_is_double(const VarType *t) {
    t = vt_unwrap_local(t);
    return (t && t->kind == VT_BASE && t->name && strcmp(t->name, "double") == 0);
}

/*
  SysV x86-64 ABI:
    - Integer class args: RDI, RSI, RDX, RCX, R8, R9 then stack (8-byte slots)
    - FP args (float/double): XMM0..XMM7 then stack (8-byte slots)
  We do "best effort" classification based on DWARF type:
    - float/double => FP class
    - everything else => integer class (incl. pointers, struct pointers)
*/
int extract_raw_args_sysv_x86_64(const struct patch_exec_context *ctx,
                                 const FuncSig *f,
                                 uint64_t *out_raw_args)
{
    if (!ctx || !f || !out_raw_args) return -1;

    /* integer arg registers */
    static const int kIntRegs[6] = {
        PATCH_X86_64_RDI,
        PATCH_X86_64_RSI,
        PATCH_X86_64_RDX,
        PATCH_X86_64_RCX,
        PATCH_X86_64_R8,
        PATCH_X86_64_R9,
    };

    size_t int_i = 0;
    size_t fp_i  = 0;

    /* Stack args start at RSP+8 (skip return address) for a probe at function entry. */
    const uint8_t *sp = (const uint8_t*)(uintptr_t)ctx->stack_pointer;  /* :contentReference[oaicite:3]{index=3} */
    const uint8_t *stackp = sp ? (sp + 8) : NULL;
    size_t stack_slots_used = 0;

    /* Try to access SSE state for XMM regs (if libpatch saved it). */
    struct patch_x86_64_legacy *sse = NULL;
    if (ctx->extended_states) { /* :contentReference[oaicite:4]{index=4} */
        /* Provided by libpatch x86_64 header: returns PATCH_OK on success. */
        (void)patch_x86_sse_state(ctx->extended_states, &sse);
    }

    for (size_t a = 0; a < f->n_args; a++) {
        const VarType *t = f->args[a];
        t = vt_unwrap_local(t);

        int is_fp = vartype_is_float_or_double(t);

        if (is_fp) {
            /* Prefer XMM0..XMM7 */
            if (sse && fp_i < 8) {
                /* In the legacy fxsave area, XMM regs are 128-bit; we read the low lane. */
                const uint64_t *xmm_base = &sse->xmm0[0];   /* contiguous: xmm0..xmm15 */
                const uint64_t lo64 = xmm_base[fp_i * 2 + 0];

                if (vartype_is_float(t)) {
                    /* float is low 32 bits of XMM */
                    uint32_t lo32 = (uint32_t)(lo64 & 0xffffffffu);
                    out_raw_args[a] = (uint64_t)lo32;
                } else {
                    /* double is low 64 bits of XMM */
                    out_raw_args[a] = lo64;
                }
                fp_i++;
                continue;
            }

            /* Spill to stack if no SSE saved or XMM regs exhausted */
            if (!stackp) return -2;
            uint64_t slot = 0;
            memcpy(&slot, stackp + stack_slots_used * 8, 8);
            out_raw_args[a] = slot;
            stack_slots_used++;
            continue;
        }

        /* Integer/pointer class */
        if (int_i < 6) {
            out_raw_args[a] = (uint64_t)ctx->general_purpose_registers[kIntRegs[int_i]]; /* :contentReference[oaicite:5]{index=5} */
            int_i++;
            continue;
        }

        /* Spill to stack */
        if (!stackp) return -3;
        uint64_t slot = 0;
        memcpy(&slot, stackp + stack_slots_used * 8, 8);
        out_raw_args[a] = slot;
        stack_slots_used++;
    }

    return 0;
}

void demo()
{
    DwarfModel *model = dwarf_scan_collect_model();
    if (!model) {
        printf("[error] failed to build DWARF model. make sure the target is compiled with debug info\n");
        return;
    }

    TraceConditionCfg cfg;
    const char *cfg_path = getenv("TRACE_CONFIG");
    if (!cfg_path) cfg_path = "config.yaml";
    if (load_trace_config(cfg_path, &cfg) != 0) {
        printf("failed to load %s\n", cfg_path);
        dwarf_model_free(model);
        return;
    }

    // for each target in cfg, print its function name and triggers
    for (size_t i = 0; i < cfg.n_targets; i++) {
        const TargetCfg *t = &cfg.targets[i];

        uint64_t offset, trigger_offset;
        dwarf_find_function_lowpc(t->func, &offset);
        dwarf_find_function_lowpc(t->trigger_func, &trigger_offset);
        
        printf("Target %zu: Func=%s, Offset=0x%lx, Recursive=%d, TriggerFunc=%s, TriggerOffset=0x%lx, Triggers=[", i, t->func, offset, t->recursive, t->trigger_func, trigger_offset);
        for (size_t j = 0; j < t->triggers.n; j++) {
            printf("%s\"%s\"", (j > 0) ? ", " : "", t->triggers.items[j]);
        }
        printf("]\n");

        const FuncSig *f = find_funcsig_by_name(model, t->trigger_func);
        printf("found function %s with %zu args\n", f->name, f->n_args);

        printf("[demo] loaded %zu trigger(s) for %s\n", t->triggers.n, t->trigger_func);

        CompiledTrigger *compiled = NULL;
        if (t->triggers.n) {
            compiled = (CompiledTrigger*)calloc(t->triggers.n, sizeof(CompiledTrigger));
            for (size_t k = 0; k < t->triggers.n; k++) {
                if (compile_trigger(&compiled[k], t->triggers.items[k], f) != 0) {
                    printf("failed to compile trigger[%zu]: %s\n", k, t->triggers.items[k]);
                }
            }
        }
        
        if (compiled) {
            for (size_t k = 0; k < t->triggers.n; k++) compiled_trigger_free(&compiled[k]);
            free(compiled);
        }
    }


    cfg_free(&cfg);
    dwarf_model_free(model);
}

__attribute__((constructor))
static void on_load(void)
{
    demo();
}

__attribute__((destructor))
static void on_unload(void)
{

}

// gcc -shared -fPIC trigger_check.c trigger_compiler.c trace_config.c -o trigger_check.so -I. -L. -ldwscan -Wl,-rpath,'$ORIGIN' -lyaml
// LD_PRELOAD=./trigger_check.so ~/Codes/cpu2017/benchspec/CPU/505.mcf_r/run/run_base_refrate_ali-test1-m64.0000/mcf_r_base.ali-test1-m64