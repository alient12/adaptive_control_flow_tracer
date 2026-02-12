#define TRACEPOINT_CREATE_PROBES
#define TRACEPOINT_DEFINE

#include "lttng_tp.h"

// gcc -c -I. lttng_tp.c

// lttng create my_session
// lttng enable-event -u wyvern:probe2
// lttng start
// run ...
// lttng stop
// lttng view my_session

// lttng destroy --all