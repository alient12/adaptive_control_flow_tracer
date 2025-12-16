#include "trace_config.h"


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

/* Schema-aware loader for:

TraceCondition:
  LogsDir: ./tracer_logs
  Targets:
  - Func: update_tree
    Recursive: false
    TriggerFunc: update_tree
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
            } else if ((st == ST_TARGETS || st == ST_TARGET) && strcmp(s, "Func") == 0) {
                free(pending_key); pending_key = xstrdup(s);
                if (!cur) cur = cfg_add_target(out);
                st = ST_TARGET;
            } else if (st == ST_TARGET && strcmp(s, "Recursive") == 0) {
                free(pending_key); pending_key = xstrdup(s);
            } else if (st == ST_TARGET && strcmp(s, "TriggerFunc") == 0) {
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
            else if (pending_key && cur && strcmp(pending_key, "Recursive") == 0) {
                cur->recursive = (strcmp(s, "true") == 0) ? 1 : 0;
                free(pending_key); pending_key = NULL;
            }
            else if (pending_key && cur && strcmp(pending_key, "TriggerFunc") == 0) {
                free(cur->trigger_func);
                cur->trigger_func = xstrdup(s);
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
            cur = NULL;
            st = ST_TARGETS;
        }

        if (ev.type == YAML_STREAM_END_EVENT) {
            yaml_event_delete(&ev);
            break;
        }

        yaml_event_delete(&ev);
    }

    free(pending_key);
    yaml_parser_delete(&parser);
    fclose(fp);

    return 0;
}

const TargetCfg *cfg_find_target(const TraceConditionCfg *cfg, const char *func_name)
{
    if (!cfg || !func_name) return NULL;
    for (size_t i = 0; i < cfg->n_targets; i++) {
        if (cfg->targets[i].func && strcmp(cfg->targets[i].func, func_name) == 0)
            return &cfg->targets[i];
    }
    return NULL;
}