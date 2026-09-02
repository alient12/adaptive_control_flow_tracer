#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <yaml.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char **items;
    size_t n;
} StringList;

typedef struct {
    char *func;
    bool has_func_lowpc;
    uint64_t func_lowpc;
    int recursive;
    char *trigger_func;
    bool has_trigger_func_lowpc;
    uint64_t trigger_func_lowpc;
    StringList triggers;
} TargetCfg;

typedef struct {
    char *logs_dir;
    TargetCfg *targets;
    size_t n_targets;
} TraceConditionCfg;

char *xstrdup(const char *s);
void cfg_free(TraceConditionCfg *cfg);
int load_trace_config(const char *path, TraceConditionCfg *out);
const TargetCfg *cfg_find_target(const TraceConditionCfg *cfg, const char *func_name, const uint64_t *func_lowpc);