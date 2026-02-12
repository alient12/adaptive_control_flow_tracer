#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER wyvern

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./lttng_tp.h"

#if !defined(_LTTNG_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _LTTNG_TP_H

#include <lttng/tracepoint.h>

LTTNG_UST_TRACEPOINT_EVENT(
    wyvern,
    probe2,
    LTTNG_UST_TP_ARGS(
        uint64_t, ip
    ),
    LTTNG_UST_TP_FIELDS(
        lttng_ust_field_integer(uint64_t, instruction_pointer, ip)
    )
)

#endif /* _LTTNG_TP_H */

#include <lttng/tracepoint-event.h>