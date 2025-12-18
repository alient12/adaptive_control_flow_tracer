// trace_shared.h
#ifndef TRACE_SHARED_H
#define TRACE_SHARED_H

#include <stdint.h>
#include <stdatomic.h>

// Shared memory object names (must match in tracer & daemon)
#define TRACE_SHM_META_NAME   "/trace_meta"
#define TRACE_SHM_EVENTS_NAME "/trace_events"

// Hard limits (can tweak as needed)
#define TRACE_MAX_CPUS        256
#define TRACE_BUF_CAPACITY    (1u << 20)   // 1M events per CPU (must be power of 2)

typedef struct {
    uint64_t tsc;     // timestamp
    uint64_t value;   // e.g., offset
} trace_event_t;

// Global metadata (shared)
typedef struct {
    uint32_t n_cpus;       // how many CPUs are actually used
    uint32_t capacity;     // events per CPU (TRACE_BUF_CAPACITY)
    uint32_t record_size;  // sizeof(trace_event_t)
    uint32_t _pad;
} trace_meta_global_t;

// Per-CPU metadata (shared)
typedef struct {
    _Atomic uint64_t head;     // next write index (monotonic, wraps via & (capacity-1))
    _Atomic uint64_t dropped;  // events dropped by producer
} trace_meta_cpu_t;

// Layout of meta shm:
//
// [ trace_meta_global_t ]
// [ trace_meta_cpu_t for cpu 0 ]
// [ trace_meta_cpu_t for cpu 1 ]
// ...
// [ trace_meta_cpu_t for cpu n_cpus-1 ]
//
// Layout of events shm:
//
// CPU 0 events: capacity * sizeof(trace_event_t)
// CPU 1 events: capacity * sizeof(trace_event_t)
// ...
// CPU n_cpus-1 events

#endif // TRACE_SHARED_H
