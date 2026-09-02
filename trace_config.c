#include "trace_config.h"

#include <errno.h>
#include <stdint.h>


char *xstrdup(const char *s)
{
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = (char*)malloc(n);
    if (!p) return NULL;
    memcpy(p, s, n);
    return p;
}

static void strlist_push(StringList *l, const char *s)
{
    if (!l || !s) return;
    char **nn = (char**)realloc(l->items, (l->n + 1) * sizeof(char*));
    if (!nn) return;
    l->items = nn;
    l->items[l->n++] = xstrdup(s);
}

static void strlist_free(StringList *l)
{
    if (!l) return;
    for (size_t i = 0; i < l->n; i++) free(l->items[i]);
    free(l->items);
    l->items = NULL;
    l->n = 0;
}

static void target_free(TargetCfg *t)
{
    if (!t) return;
    free(t->func);
    free(t->trigger_func);
    strlist_free(&t->triggers);
    memset(t, 0, sizeof(*t));
}

void cfg_free(TraceConditionCfg *cfg)
{
    if (!cfg) return;
    free(cfg->logs_dir);
    for (size_t i = 0; i < cfg->n_targets; i++) target_free(&cfg->targets[i]);
    free(cfg->targets);
    memset(cfg, 0, sizeof(*cfg));
}

static TargetCfg *cfg_add_target(TraceConditionCfg *cfg)
{
    TargetCfg *nn = (TargetCfg*)realloc(cfg->targets, (cfg->n_targets + 1) * sizeof(TargetCfg));
    if (!nn) return NULL;
    cfg->targets = nn;
    TargetCfg *t = &cfg->targets[cfg->n_targets++];
    memset(t, 0, sizeof(*t));
    return t;
}

static int parse_u64_scalar(const char *s, uint64_t *out)
{
    if (!s || !*s || !out) return -1;

    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0') return -1;

    *out = (uint64_t)v;
    return 0;
}

static int target_is_valid(const TargetCfg *t)
{
    if (!t) return 0;
    if (!t->func && !t->has_func_lowpc) return 0;
    if (!t->trigger_func && !t->has_trigger_func_lowpc) return 0;
    return 1;
}

/* Schema-aware loader for:

TraceCondition:
  LogsDir: ./tracer_logs
  Targets:
  - Func: update_tree
        # FuncOffset: 0x1234
    Recursive: false
    TriggerFunc: update_tree
        # TriggerOffset: 0x1234
    Triggers:
      - arg0 == 10 && arg1 < 20
      - arg5.orientation = 2 || arg5.child.orientation = 3
      - auto arg0 arg1
*/
int load_trace_config(const char *path, TraceConditionCfg *out)
{
    if (!path || !out) return -1;
    memset(out, 0, sizeof(*out));

    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    yaml_parser_t parser;
    yaml_event_t ev;
    if (!yaml_parser_initialize(&parser)) { fclose(fp); return -1; }
    yaml_parser_set_input_file(&parser, fp);

    enum { ST_NONE=0, ST_TC, ST_TARGETS, ST_TARGET, ST_TRIGGERS } st = ST_NONE;

    char *pending_key = NULL;
    TargetCfg *cur = NULL;
    int rc = -1;

    for (;;) {
        if (!yaml_parser_parse(&parser, &ev)) break;

        if (ev.type == YAML_SCALAR_EVENT) {
            const char *s = (const char*)ev.data.scalar.value;

            /* Keys */
            if (strcmp(s, "TraceCondition") == 0) {
                st = ST_TC;
            } else if (st == ST_TC && strcmp(s, "LogsDir") == 0) {
                free(pending_key); pending_key = xstrdup(s);
            } else if (st == ST_TC && strcmp(s, "Targets") == 0) {
                st = ST_TARGETS;
            } else if ((st == ST_TARGETS || st == ST_TARGET) &&
                       (strcmp(s, "Func") == 0 || strcmp(s, "FuncOffset") == 0 ||
                        strcmp(s, "Recursive") == 0 || strcmp(s, "TriggerFunc") == 0 ||
                        strcmp(s, "TriggerOffset") == 0 || strcmp(s, "Triggers") == 0)) {
                if (!cur) cur = cfg_add_target(out);
                if (!cur) {
                    yaml_event_delete(&ev);
                    goto done;
                }
                st = ST_TARGET;
                if (strcmp(s, "Func") == 0) {
                    free(pending_key); pending_key = xstrdup(s);
                } else if (strcmp(s, "FuncOffset") == 0) {
                    free(pending_key); pending_key = xstrdup(s);
                } else if (strcmp(s, "Recursive") == 0) {
                    free(pending_key); pending_key = xstrdup(s);
                } else if (strcmp(s, "TriggerFunc") == 0) {
                    free(pending_key); pending_key = xstrdup(s);
                } else if (strcmp(s, "TriggerOffset") == 0) {
                    free(pending_key); pending_key = xstrdup(s);
                } else if (strcmp(s, "Triggers") == 0) {
                    st = ST_TRIGGERS;
                }
            } else if (st == ST_TARGET && strcmp(s, "Recursive") == 0) {
                free(pending_key); pending_key = xstrdup(s);
            } else if (st == ST_TARGET && strcmp(s, "FuncOffset") == 0) {
                free(pending_key); pending_key = xstrdup(s);
            } else if (st == ST_TARGET && strcmp(s, "TriggerFunc") == 0) {
                free(pending_key); pending_key = xstrdup(s);
            } else if (st == ST_TARGET && strcmp(s, "TriggerOffset") == 0) {
                free(pending_key); pending_key = xstrdup(s);
            } else if (st == ST_TARGET && strcmp(s, "Triggers") == 0) {
                st = ST_TRIGGERS;
            }
            /* Values */
            else if (pending_key && st == ST_TC && strcmp(pending_key, "LogsDir") == 0) {
                free(out->logs_dir);
                out->logs_dir = xstrdup(s);
                free(pending_key); pending_key = NULL;
            }
            else if (pending_key && cur && strcmp(pending_key, "Func") == 0) {
                free(cur->func);
                cur->func = xstrdup(s);
                free(pending_key); pending_key = NULL;
            }
            else if (pending_key && cur && strcmp(pending_key, "FuncOffset") == 0) {
                if (parse_u64_scalar(s, &cur->func_lowpc) != 0) {
                    yaml_event_delete(&ev);
                    goto done;
                }
                cur->has_func_lowpc = true;
                free(pending_key); pending_key = NULL;
            }
            else if (pending_key && cur && strcmp(pending_key, "Recursive") == 0) {
                cur->recursive = (strcmp(s, "true") == 0) ? 1 : 0;
                free(pending_key); pending_key = NULL;
            }
            else if (pending_key && cur && strcmp(pending_key, "TriggerFunc") == 0) {
                free(cur->trigger_func);
                cur->trigger_func = xstrdup(s);
                free(pending_key); pending_key = NULL;
            }
            else if (pending_key && cur && strcmp(pending_key, "TriggerOffset") == 0) {
                if (parse_u64_scalar(s, &cur->trigger_func_lowpc) != 0) {
                    yaml_event_delete(&ev);
                    goto done;
                }
                cur->has_trigger_func_lowpc = true;
                free(pending_key); pending_key = NULL;
            }
            else if (st == ST_TRIGGERS && cur) {
                /* Each scalar inside Triggers sequence is a trigger string */
                strlist_push(&cur->triggers, s);
            }
        }

        if (ev.type == YAML_SEQUENCE_END_EVENT && st == ST_TRIGGERS) {
            st = ST_TARGET;
        }

        if (ev.type == YAML_MAPPING_END_EVENT && st == ST_TARGET) {
            /* End of one target mapping: next list item will create new target */
            if (!target_is_valid(cur)) {
                fprintf(stderr, "invalid target: Func/FuncOffset and TriggerFunc/TriggerOffset are each required\n");
                yaml_event_delete(&ev);
                goto done;
            }
            cur = NULL;
            st = ST_TARGETS;
        }

        if (ev.type == YAML_STREAM_END_EVENT) {
            yaml_event_delete(&ev);
            break;
        }

        yaml_event_delete(&ev);
    }

    if (cur || st == ST_TARGET) {
        if (!target_is_valid(cur)) {
            fprintf(stderr, "invalid target: Func/FuncOffset and TriggerFunc/TriggerOffset are each required\n");
            goto done;
        }
    }

    rc = 0;

done:
    free(pending_key);
    yaml_parser_delete(&parser);
    fclose(fp);
    if (rc != 0) cfg_free(out);
    return rc;
}

const TargetCfg *cfg_find_target(const TraceConditionCfg *cfg, const char *func_name, const uint64_t *func_lowpc)
{
    if (!cfg) return NULL;
    for (size_t i = 0; i < cfg->n_targets; i++) {
        const TargetCfg *t = &cfg->targets[i];

        if (t->func) {
            if (!func_name || strcmp(t->func, func_name) != 0)
                continue;
        }

        if (t->has_func_lowpc) {
            if (!func_lowpc || *func_lowpc != t->func_lowpc)
                continue;
        }

        if (!t->func && !t->has_func_lowpc)
            continue;

        return t;
    }
    return NULL;
}