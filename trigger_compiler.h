/*
  trigger_compiler.h
  ==================
  Header file for trigger_compiler.c - DWARF-driven argument metadata + YAML-driven trigger evaluation
  
  This module provides:
  - Member path resolution from struct/union types
  - Trigger expression compilation and evaluation
  - Precompiled AST-based trigger language interpreter
  
  The trigger language supports:
    * variables: argN or argN.member.submember
    * comparisons: == != < <= > >= (= is treated as ==)
    * boolean operations: && ||
    * literals: int (10), hex (0x10), float (3.14), string ("abc")
  
  See trigger_compiler.c for implementation details.
*/

#ifndef TRIGGER_COMPILER_H
#define TRIGGER_COMPILER_H

#include <stdint.h>
#include <stddef.h>
#include "trace_config.h"

/* ======================= Shared model (from libdwscan) ======================= */
#include "libdwscan.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ======================= Value representation ======================= */

typedef enum {
    VK_INT,
    VK_FLOAT,
    VK_DOUBLE,
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


/* ======================= Trigger expression AST compilation ======================= */

/**
 * Opaque type for compiled trigger expressions
 * Contains precompiled AST ready for fast evaluation
 */
typedef struct {
    void *root;           /* AST root (Node*) - opaque */
    char *expr_owned;     /* Owned copy of original expression */
} CompiledTrigger;

/**
 * Compile a trigger expression string into an AST
 * The compiled trigger can be evaluated many times efficiently.
 *
 * Expression syntax:
 *   - Variables: arg0, arg1, arg0.member, arg0.member.submember
 *   - Comparisons: ==, !=, <, <=, >, >=, = (treated as ==)
 *   - Boolean ops: && (AND), || (OR)
 *   - Literals: integers (42, 0x10), floats (3.14), strings ("hello")
 *   - Parentheses for grouping: (arg0 > 5)
 *
 * Examples:
 *   "arg0 == 10"
 *   "arg0 > 5 && arg1 < 20"
 *   "arg0.port == 8080"
 *   "(arg0.child.value >= 100) || (arg1 == 0)"
 *
 * @param out Output CompiledTrigger (must be zero-initialized)
 * @param expr Trigger expression string
 * @param sig Function signature (used to resolve arg types)
 * @return 0 on success, negative on error
 */
int compile_trigger(CompiledTrigger *out, const char *expr, const FuncSig *sig);

/**
 * Free resources associated with a compiled trigger
 * @param t Pointer to CompiledTrigger (may be NULL)
 */
void compiled_trigger_free(CompiledTrigger *t);

/**
 * Evaluate a compiled trigger expression
 * Fast path: trigger is parsed only once at compilation time
 *
 * @param t Compiled trigger expression
 * @param sig Function signature
 * @param raw_args Array of raw argument values (register or pointer values)
 * @return Non-zero (true) if trigger condition is met, zero (false) otherwise
 */
int eval_compiled_trigger(const CompiledTrigger *t, const FuncSig *sig, const uint64_t *raw_args);



/* ======================= Demo pipeline ======================= */

/**
 * Demonstration pipeline showing full workflow:
 * 1. Collect DWARF model
 * 2. Find function by name
 * 3. Load trace configuration from YAML
 * 4. Compile trigger expressions
 * 5. Evaluate triggers with dummy data
 * 6. Benchmark evaluation performance
 *
 * Looks for config file in TRACE_CONFIG environment variable, or "config.yaml" by default.
 *
 * @param func_name Name of function to process
 */
void demo_pipeline(const char *func_name);

#ifdef __cplusplus
}
#endif

#endif /* TRIGGER_COMPILER_H */
