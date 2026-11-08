/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Yunzhan contributors.
 * Fixed-size admission state for mod_yunzhan_cc; no request bytes or I/O.
 */
#ifndef YUNZHAN_APACHE_CC_CORE_H
#define YUNZHAN_APACHE_CC_CORE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdatomic.h>

#if ATOMIC_INT_LOCK_FREE != 2
#error "Apache CC requires always-lock-free unsigned-int commits"
#endif

#define YZ_CC_ROWS 4096u
#define YZ_CC_PROBES 128u
#define YZ_CC_MAX_ZONES 21u
#define YZ_CC_NS UINT64_C(1000000000)

typedef struct {
    unsigned char key[32]; /* HMAC-SHA256, not an address or URL */
    uint64_t at_ns;
    uint64_t credit;
    uint32_t rate;
    uint32_t burst;
    uint32_t used;
} yz_cc_value;

typedef struct {
    _Atomic unsigned int active;
    yz_cc_value value[2];
} yz_cc_row;

typedef struct {
    unsigned char key[32];
    uint32_t rate;
    uint32_t burst; /* extra immediate admissions, in addition to this one */
} yz_cc_zone;

static uint64_t yz_cc_capacity(uint32_t burst)
{
    return ((uint64_t)burst + 1) * YZ_CC_NS;
}

/* The caller owns a process-shared robust mutex. An owner dying while writing
 * an inactive copy leaves the previously committed value intact. A death
 * between zone commits may overcharge a request that never reached a handler;
 * it cannot undercharge any request that was actually admitted. */
static yz_cc_value yz_cc_read(const yz_cc_row *row)
{
    unsigned int active = atomic_load_explicit(&row->active, memory_order_acquire);
    return row->value[active & 1u];
}

static void yz_cc_commit(yz_cc_row *row, const yz_cc_value *value)
{
    unsigned int next = (atomic_load_explicit(&row->active, memory_order_relaxed) ^ 1u) & 1u;
    row->value[next] = *value;
    atomic_store_explicit(&row->active, next, memory_order_release);
}

static uint64_t yz_cc_refill(const yz_cc_value *v, uint64_t now)
{
    uint64_t cap = yz_cc_capacity(v->burst);
    uint64_t elapsed = now >= v->at_ns ? now - v->at_ns : 0;
    uint64_t credit = v->credit > cap ? cap : v->credit;
    uint64_t missing = cap - credit;
    /* Saturate before multiplying, including a centuries-long idle period. */
    if (elapsed >= (missing + v->rate - 1) / v->rate)
        return cap;
    return credit + elapsed * v->rate;
}

static int yz_cc_pending(size_t index, const size_t *chosen, size_t count)
{
    size_t i;
    for (i = 0; i < count; ++i)
        if (chosen[i] == index) return 1;
    return 0;
}

/* Lookup scans the entire bounded probe window before choosing an empty or
 * refill-idle row. Stopping at an empty row would lose keys displaced by an
 * earlier eviction. Active quotas are never evicted to admit a new address. */
static int yz_cc_find(yz_cc_row *rows, const yz_cc_zone *zone, uint64_t now,
                      const size_t *chosen, size_t count, size_t *found)
{
    uint32_t hash;
    size_t i, spare = YZ_CC_ROWS;
    memcpy(&hash, zone->key, sizeof(hash));
    for (i = 0; i < YZ_CC_PROBES; ++i) {
        size_t index = ((size_t)hash + i) & (YZ_CC_ROWS - 1u);
        yz_cc_value v;
        if (yz_cc_pending(index, chosen, count)) continue;
        v = yz_cc_read(&rows[index]);
        if (v.used && (v.used != 1 || v.rate < 1 || v.rate > 200 || v.burst < 1 || v.burst > 1000))
            return -1;
        if (v.used && memcmp(v.key, zone->key, sizeof(v.key)) == 0) {
            if (v.rate != zone->rate || v.burst != zone->burst) return -1;
            *found = index;
            return 1;
        }
        if (spare == YZ_CC_ROWS && (!v.used || yz_cc_refill(&v, now) == yz_cc_capacity(v.burst)))
            spare = index;
    }
    if (spare == YZ_CC_ROWS) return -1;
    *found = spare;
    return 0;
}

/* 1 = admitted, 0 = over rate, -1 = bounded table/invalid state unavailable.
 * Every matching zone is checked under the same lock. A denial consumes none
 * of the other zones, so a rejected URL cannot drain an unrelated allowance. */
static int yz_cc_admit(yz_cc_row *rows, const yz_cc_zone *zones, size_t count,
                       uint64_t now, uint64_t *retry_ns)
{
    size_t i, chosen[YZ_CC_MAX_ZONES];
    yz_cc_value next[YZ_CC_MAX_ZONES];
    *retry_ns = 0;
    if (!rows || !zones || count == 0 || count > YZ_CC_MAX_ZONES || now == 0)
        return -1;
    for (i = 0; i < count; ++i) {
        int existing;
        size_t j;
        uint64_t credit, stamp = now;
        if (zones[i].rate < 1 || zones[i].rate > 200 || zones[i].burst < 1 || zones[i].burst > 1000)
            return -1;
        for (j = 0; j < i; ++j)
            if (memcmp(zones[i].key, zones[j].key, sizeof(zones[i].key)) == 0) return -1;
        existing = yz_cc_find(rows, &zones[i], now, chosen, i, &chosen[i]);
        if (existing < 0) return -1;
        next[i] = yz_cc_read(&rows[chosen[i]]);
        credit = existing ? yz_cc_refill(&next[i], now) : yz_cc_capacity(zones[i].burst);
        if (credit < YZ_CC_NS) {
            *retry_ns = (YZ_CC_NS - credit + zones[i].rate - 1) / zones[i].rate;
            return 0;
        }
        /* A monotonic-clock regression must never move the refill origin
         * backwards and award the same elapsed interval twice. */
        if (existing && next[i].at_ns > stamp) stamp = next[i].at_ns;
        memset(&next[i], 0, sizeof(next[i]));
        memcpy(next[i].key, zones[i].key, sizeof(next[i].key));
        next[i].at_ns = stamp;
        next[i].credit = credit - YZ_CC_NS;
        next[i].rate = zones[i].rate;
        next[i].burst = zones[i].burst;
        next[i].used = 1;
    }
    for (i = 0; i < count; ++i)
        yz_cc_commit(&rows[chosen[i]], &next[i]);
    return 1;
}

#endif
