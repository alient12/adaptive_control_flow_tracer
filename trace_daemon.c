#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <inttypes.h>   // for PRIu64, PRIx64

#include "trace_shared.h"

static volatile sig_atomic_t g_stop = 0;

static void handle_sigint(int sig) {
    (void)sig;
    g_stop = 1;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

typedef struct {
    uint32_t cpu;
    uint32_t pad;
    uint64_t tsc;
    uint64_t time_ns;
    uint64_t value;
} trace_disk_record_t;

int main(int argc, char **argv)
{
    int debug = 0;
    const char *out_path = "trace.bin";

    // Usage:
    //   ./trace_daemon                 -> writes trace.bin
    //   ./trace_daemon --debug         -> prints records + writes trace.bin
    //   ./trace_daemon --debug out.bin -> prints + writes out.bin
    //   ./trace_daemon out.bin         -> no debug, writes out.bin
    if (argc >= 2) {
        if (strcmp(argv[1], "--debug") == 0) {
            debug = 1;
            if (argc >= 3) {
                out_path = argv[2];
            }
        } else {
            out_path = argv[1];
        }
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    /* ---------- 1) META shm: create if needed, map, then WAIT for tracer ---------- */

    size_t meta_size = sizeof(trace_meta_global_t)
                     + TRACE_MAX_CPUS * sizeof(trace_meta_cpu_t);

    int meta_fd = shm_open(TRACE_SHM_META_NAME, O_CREAT | O_RDWR, 0600);
    if (meta_fd < 0) {
        perror("shm_open(meta)");
        return 1;
    }

    if (ftruncate(meta_fd, (off_t)meta_size) < 0) {
        perror("ftruncate(meta)");
        close(meta_fd);
        return 1;
    }

    void *meta_base = mmap(NULL, meta_size,
                           PROT_READ | PROT_WRITE,
                           MAP_SHARED, meta_fd, 0);
    close(meta_fd);
    if (meta_base == MAP_FAILED) {
        perror("mmap(meta)");
        return 1;
    }

    trace_meta_global_t *gmeta = (trace_meta_global_t *)meta_base;
    trace_meta_cpu_t    *cmeta = (trace_meta_cpu_t *)((uint8_t *)meta_base
                                 + sizeof(trace_meta_global_t));

    // Wait for tracer to fill global meta: n_cpus, capacity, record_size
    fprintf(stderr, "trace_daemon: waiting for tracer to init meta...\n");
    while (!g_stop) {
        uint32_t n_cpus   = atomic_load_explicit(&gmeta->n_cpus,      memory_order_acquire);
        uint32_t capacity = atomic_load_explicit(&gmeta->capacity,    memory_order_acquire);
        uint32_t rec_size = atomic_load_explicit(&gmeta->record_size, memory_order_acquire);

        if (n_cpus > 0 && capacity > 0 && rec_size == sizeof(trace_event_t)) {
            break;
        }

        struct timespec ts = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 }; // 10 ms
        nanosleep(&ts, NULL);
    }

    if (g_stop) {
        munmap(meta_base, meta_size);
        return 0;
    }

    uint32_t n_cpus   = gmeta->n_cpus;
    uint32_t capacity = gmeta->capacity;
    uint32_t rec_size = gmeta->record_size;
    uint32_t cycles_per_ns = gmeta->cycles_per_ns;

    if (n_cpus > TRACE_MAX_CPUS) {
        fprintf(stderr, "n_cpus (%u) > TRACE_MAX_CPUS (%u), clamping\n",
                n_cpus, TRACE_MAX_CPUS);
        n_cpus = TRACE_MAX_CPUS;
    }

    if (capacity == 0 || rec_size != sizeof(trace_event_t)) {
        fprintf(stderr, "Invalid meta after init: capacity=%u, record_size=%u (expected %zu)\n",
                capacity, rec_size, sizeof(trace_event_t));
        munmap(meta_base, meta_size);
        return 1;
    }

    fprintf(stderr, "trace_daemon: meta ready: n_cpus=%u, capacity=%u, rec_size=%u, cycles_per_ns=%u\n",
            n_cpus, capacity, rec_size, cycles_per_ns);
        
    
    // Stats: how much data we've written so far
    uint64_t total_bytes_written = 0;
    uint64_t last_bytes_reported = 0;

    // Existing flush config
    const uint64_t FLUSH_INTERVAL_MS = 200;
    const uint64_t WATERMARK         = (uint64_t)capacity * 3 / 4;

    // New: stats print interval (e.g., every 1s)
    const uint64_t STATS_INTERVAL_MS = 1000;
    uint64_t next_flush_deadline     = now_ms() + FLUSH_INTERVAL_MS;
    uint64_t next_stats_deadline     = now_ms() + STATS_INTERVAL_MS;

    /* ---------- 2) EVENTS shm: create if needed, map big enough ---------- */

    size_t per_cpu_bytes = (size_t)TRACE_BUF_CAPACITY * sizeof(trace_event_t);
    size_t events_size   = (size_t)TRACE_MAX_CPUS * per_cpu_bytes;

    int events_fd = shm_open(TRACE_SHM_EVENTS_NAME, O_CREAT | O_RDWR, 0600);
    if (events_fd < 0) {
        perror("shm_open(events)");
        munmap(meta_base, meta_size);
        return 1;
    }
    if (ftruncate(events_fd, (off_t)events_size) < 0) {
        perror("ftruncate(events)");
        close(events_fd);
        munmap(meta_base, meta_size);
        return 1;
    }

    void *events_base = mmap(NULL, events_size,
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED, events_fd, 0);
    close(events_fd);
    if (events_base == MAP_FAILED) {
        perror("mmap(events)");
        munmap(meta_base, meta_size);
        return 1;
    }

    /* ---------- 3) Open output, main loop, etc. ---------- */
    FILE *out = fopen(out_path, "wb");
    if (!out) {
        perror("fopen(output)");
        munmap(events_base, events_size);
        munmap(meta_base, meta_size);
        return 1;
    }

    uint64_t *tail = calloc(n_cpus, sizeof(uint64_t));
    if (!tail) {
        perror("calloc(tail)");
    } else {
        // Start consuming from "now": skip everything that was already in the buffer
        for (uint32_t cpu = 0; cpu < n_cpus; ++cpu) {
            uint64_t head = atomic_load_explicit(&cmeta[cpu].head, memory_order_acquire);
            tail[cpu] = head;
        }
    }

    next_flush_deadline     = now_ms() + FLUSH_INTERVAL_MS;

    fprintf(stderr, "trace_daemon: writing to %s; Ctrl+C to stop.\n", out_path);
    // 5) Main loop
    while (!g_stop) {
        uint64_t now      = now_ms();
        bool     busy     = false;
        bool     do_flush = false;

        if (now >= next_flush_deadline) {
            do_flush = true;  // time-based trigger
            next_flush_deadline = now + FLUSH_INTERVAL_MS;
        }

        for (uint32_t cpu = 0; cpu < n_cpus; ++cpu) {
            trace_meta_cpu_t *m   = &cmeta[cpu];
            trace_event_t    *buf = (trace_event_t *)((uint8_t *)events_base
                                     + (size_t)cpu * per_cpu_bytes);

            uint64_t head = atomic_load_explicit(&m->head, memory_order_acquire);
            uint64_t t    = tail ? tail[cpu] : 0;
            uint64_t avail = head - t;

            if (avail == 0) {
                continue;
            }

            if (avail >= WATERMARK) {
                busy = true;
                do_flush = true;
            }

            if (!do_flush) {
                continue;
            }

            while (t < head) {
                uint64_t idx = t & (capacity - 1);
                trace_event_t ev = buf[idx];

                trace_disk_record_t rec;
                rec.cpu   = cpu;
                rec.pad   = 0;
                rec.tsc   = ev.tsc;
                rec.time_ns = ev.tsc / (uint64_t)cycles_per_ns;
                rec.value = ev.value;

                if (debug) {
                    // print in both decimal and hex for sanity
                    printf("CPU=%u TSC=%" PRIu64 " (0x%016" PRIx64 ") Time(ns)=%" PRIu64 "  VALUE=0x%016" PRIx64 "\n",
                        rec.cpu,
                        rec.tsc,
                        rec.tsc,
                        rec.time_ns,
                        rec.value);
                }

                size_t written = fwrite(&rec, sizeof(rec), 1, out);
                (void)written; // ignore errors here; real code should handle

                total_bytes_written += sizeof(rec);

                t++;
            }

            if (tail) tail[cpu] = head;
        }

        if (do_flush) {
            fflush(out);
        }

        if (now >= next_stats_deadline) {
            if (total_bytes_written != last_bytes_reported) {
                double mb = (double)total_bytes_written / (1024.0 * 1024.0);
                fprintf(stderr, "trace_daemon: total %.2f MB written\n", mb);
                last_bytes_reported = total_bytes_written;
            }
            next_stats_deadline = now + STATS_INTERVAL_MS;
        }

        if (!busy && !do_flush) {
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = 5 * 1000 * 1000; // 5 ms
            nanosleep(&ts, NULL);
        }
    }

    fprintf(stderr, "trace_daemon: stopping, final drain.\n");

    // Final drain before exit
    for (uint32_t cpu = 0; cpu < n_cpus; ++cpu) {
        trace_meta_cpu_t *m   = &cmeta[cpu];
        trace_event_t    *buf = (trace_event_t *)((uint8_t *)events_base
                                 + (size_t)cpu * per_cpu_bytes);

        uint64_t head = atomic_load_explicit(&m->head, memory_order_acquire);
        uint64_t t    = tail ? tail[cpu] : 0;

        while (t < head) {
            uint64_t idx = t & (capacity - 1);
            trace_event_t ev = buf[idx];

            trace_disk_record_t rec;
            rec.cpu   = cpu;
            rec.pad   = 0;
            rec.tsc   = ev.tsc;
            rec.time_ns = ev.tsc / (uint64_t)cycles_per_ns;
            rec.value = ev.value;

            fwrite(&rec, sizeof(rec), 1, out);
            t++;
        }

        if (tail) tail[cpu] = head;
    }

    fflush(out);
    fclose(out);

    free(tail);
    munmap(events_base, events_size);
    munmap(meta_base, meta_size);

    return 0;
}

// gcc -O2 -Wall -Wextra -std=c11 -o trace_daemon trace_daemon.c -lrt
// ./trace_daemon --debug
