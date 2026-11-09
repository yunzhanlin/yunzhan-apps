/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Yunzhan contributors.
 * Native, per-vhost admission control. Linux AMD64/ARM64, Apache 2.4.
 * No bodies, queries or credential headers in events; no network clients or shell commands.
 */
#define _GNU_SOURCE
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "apr_strings.h"
#include "apr_time.h"
#include "apache-cc-core.h"
#include "apache-cc-log.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>

#define YZ_CC_ENGINE "1.0.0"
#define YZ_CC_SITES 64u
#define YZ_CC_STATE_SITES (YZ_CC_SITES * 2u)
#define YZ_CC_RULES 20u
#define YZ_CC_RETAINED "yunzhan_cc_1_fixed4096_dualcommit_v1"
#define YZ_CC_MAGIC UINT64_C(0x797a636331000001)
#ifndef YZ_CC_LOG_PATH
#define YZ_CC_LOG_PATH "/var/lib/panel-apache-body/cc-events.log"
#endif

module AP_MODULE_DECLARE_DATA yunzhan_cc_module;

typedef struct {
    pthread_mutex_t mutex;
    _Atomic unsigned int valid;
    char site_id[33];
    yz_cc_row rows[YZ_CC_ROWS];
} yz_cc_site_state;

typedef struct {
    uint64_t magic;
    unsigned char secret[32];
    yz_cc_site_state sites[YZ_CC_STATE_SITES];
} yz_cc_shared;

typedef struct {
    char id[33];
    char path[257];
    size_t length;
    int prefix;
    unsigned int rate, burst;
} yz_cc_rule;

typedef struct {
    char site_id[33], fingerprint[65];
    int observe, off;
    unsigned int rate, burst;
    size_t rule_count;
    yz_cc_rule rules[YZ_CC_RULES];
    yz_cc_site_state *state;
} yz_cc_config;

typedef struct {
    const char *path;
    const char *reason;
    const char *site_id;
    int charged, result, observe, logged;
} yz_cc_request;

static yz_cc_shared *yz_cc_memory;

static int yz_cc_hex(const char *s, size_t n)
{
    size_t i;
    if (!s || strlen(s) != n) return 0;
    for (i = 0; i < n; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    return 1;
}

static int yz_cc_number(const char *text, unsigned int min, unsigned int max, unsigned int *out)
{
    unsigned long v = 0;
    const char *p;
    if (!text || !*text || strlen(text) > 4) return 0;
    for (p = text; *p; ++p) {
        if (*p < '0' || *p > '9') return 0;
        v = v * 10 + (unsigned int)(*p - '0');
    }
    if (v < min || v > max) return 0;
    *out = (unsigned int)v;
    return 1;
}

static void *yz_cc_create(apr_pool_t *pool, server_rec *server)
{
    (void)server;
    return apr_pcalloc(pool, sizeof(yz_cc_config));
}

static const char *yz_cc_set_site(cmd_parms *cmd, void *dummy, int argc, char *const argv[])
{
    yz_cc_config *c = ap_get_module_config(cmd->server->module_config, &yunzhan_cc_module);
    (void)dummy;
    if (!cmd->server->is_virtual || argc != 5 || c->site_id[0] ||
        !yz_cc_hex(argv[0], 32) || (strcmp(argv[1], "block") && strcmp(argv[1], "observe") && strcmp(argv[1], "off")) ||
        !yz_cc_number(argv[2], 5, 200, &c->rate) ||
        !yz_cc_number(argv[3], 1, 1000, &c->burst) || !yz_cc_hex(argv[4], 64))
        return "YunzhanCCSite requires one managed vhost, unique site, block/observe/off, rate, burst and exact fingerprint";
    memcpy(c->site_id, argv[0], 33);
    memcpy(c->fingerprint, argv[4], 65);
    c->observe = strcmp(argv[1], "observe") == 0;
    c->off = strcmp(argv[1], "off") == 0;
    return NULL;
}

static unsigned int yz_cc_nibble(char c)
{
    return (unsigned int)(c <= '9' ? c - '0' : c - 'a' + 10);
}

static const char *yz_cc_set_rule(cmd_parms *cmd, void *dummy, int argc, char *const argv[])
{
    yz_cc_config *c = ap_get_module_config(cmd->server->module_config, &yunzhan_cc_module);
    yz_cc_rule *rule;
    size_t i, bytes;
    (void)dummy;
    if (!cmd->server->is_virtual || !c->site_id[0] || argc != 5 || c->rule_count >= YZ_CC_RULES ||
        !yz_cc_hex(argv[0], 32) || (strcmp(argv[2], "exact") && strcmp(argv[2], "prefix")))
        return "YunzhanCCRule requires a configured managed vhost and at most twenty closed rules";
    bytes = strlen(argv[1]) / 2;
    if (bytes < 1 || bytes > 256 || !yz_cc_hex(argv[1], bytes * 2))
        return "YunzhanCCRule path must be one to 256 literal hex-encoded bytes";
    for (i = 0; i < c->rule_count; ++i)
        if (strcmp(c->rules[i].id, argv[0]) == 0) return "YunzhanCCRule identifier is duplicated";
    rule = &c->rules[c->rule_count];
    if (!yz_cc_number(argv[3], 1, 200, &rule->rate) || !yz_cc_number(argv[4], 1, 1000, &rule->burst))
        return "YunzhanCCRule rate or burst is outside its closed range";
    for (i = 0; i < bytes; ++i) {
        unsigned int v = yz_cc_nibble(argv[1][i * 2]) * 16 + yz_cc_nibble(argv[1][i * 2 + 1]);
        if (v < 32 || v == 127 || v == '?' || v == '#') return "YunzhanCCRule path contains a forbidden byte";
        rule->path[i] = (char)v;
    }
    if (rule->path[0] != '/') return "YunzhanCCRule path must be absolute";
    rule->path[bytes] = '\0';
    rule->length = bytes;
    rule->prefix = strcmp(argv[2], "prefix") == 0;
    memcpy(rule->id, argv[0], 33);
    c->rule_count++;
    return NULL;
}

static int yz_cc_clock(uint64_t *now)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0 || ts.tv_sec < 0 ||
        (uint64_t)ts.tv_sec > (UINT64_MAX - YZ_CC_NS) / YZ_CC_NS) return 0;
    *now = (uint64_t)ts.tv_sec * YZ_CC_NS + (uint64_t)ts.tv_nsec;
    return *now != 0;
}

/* Never wait indefinitely for a paused worker. Robust ownership recovery plus
 * the core's inactive-copy commit preserves quotas after SIGKILL. */
static int yz_cc_lock(pthread_mutex_t *mutex)
{
    uint64_t start, now;
    struct timespec pause = {0, 50000};
    if (!yz_cc_clock(&start)) return 0;
    do {
        int result = pthread_mutex_trylock(mutex);
        if (result == 0) return 1;
        if (result == EOWNERDEAD) {
            if (pthread_mutex_consistent(mutex) == 0) return 1;
            (void)pthread_mutex_unlock(mutex);
            return 0;
        }
        if (result != EBUSY || !yz_cc_clock(&now) || now < start || now - start >= UINT64_C(5000000))
            return 0;
        (void)nanosleep(&pause, NULL);
    } while (1);
}

static int yz_cc_initialize(void)
{
    pthread_mutexattr_t attr;
    size_t i;
    yz_cc_shared **retained = ap_retained_data_get(YZ_CC_RETAINED);
    if (!retained) retained = ap_retained_data_create(YZ_CC_RETAINED, sizeof(*retained));
    if (!retained) return 0;
    if (*retained) {
        yz_cc_memory = *retained;
        return yz_cc_memory->magic == YZ_CC_MAGIC;
    }
    yz_cc_memory = mmap(NULL, sizeof(*yz_cc_memory), PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (yz_cc_memory == MAP_FAILED) { yz_cc_memory = NULL; return 0; }
    /* Anonymous mappings start zeroed. Do not touch every site's table:
     * inactive slots consume virtual space, not seventy MiB of resident RAM. */
    if (RAND_bytes(yz_cc_memory->secret, sizeof(yz_cc_memory->secret)) != 1 ||
        pthread_mutexattr_init(&attr) != 0) goto failed;
    if (pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0 ||
        pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST) != 0) {
        (void)pthread_mutexattr_destroy(&attr);
        goto failed;
    }
    for (i = 0; i < YZ_CC_STATE_SITES; ++i) {
        atomic_init(&yz_cc_memory->sites[i].valid, 0);
        if (pthread_mutex_init(&yz_cc_memory->sites[i].mutex, &attr) != 0) {
            while (i) (void)pthread_mutex_destroy(&yz_cc_memory->sites[--i].mutex);
            (void)pthread_mutexattr_destroy(&attr);
            goto failed;
        }
    }
    (void)pthread_mutexattr_destroy(&attr);
    yz_cc_memory->magic = YZ_CC_MAGIC;
    *retained = yz_cc_memory;
    return 1;
failed:
    (void)munmap(yz_cc_memory, sizeof(*yz_cc_memory));
    yz_cc_memory = NULL;
    return 0;
}

static int yz_cc_idle(const yz_cc_site_state *state, uint64_t now)
{
    size_t i;
    if (!atomic_load_explicit(&state->valid, memory_order_acquire)) return 1;
    for (i = 0; i < YZ_CC_ROWS; ++i) {
        yz_cc_value v = yz_cc_read(&state->rows[i]);
        if (!v.used) continue;
        if (v.used != 1 || v.rate < 1 || v.rate > 200 || v.burst < 1 || v.burst > 1000 ||
            yz_cc_refill(&v, now) != yz_cc_capacity(v.burst)) return 0;
    }
    return 1;
}

static int yz_cc_post_config(apr_pool_t *pool, apr_pool_t *log, apr_pool_t *temporary, server_rec *server)
{
    yz_cc_config *active[YZ_CC_SITES];
    size_t count = 0, i, j;
    server_rec *s;
    (void)pool; (void)log; (void)temporary;
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) return OK;
    for (s = server; s; s = s->next) {
        yz_cc_config *c = ap_get_module_config(s->module_config, &yunzhan_cc_module);
        if (!c || !c->site_id[0] || c->off) continue;
        if (count == YZ_CC_SITES) goto invalid;
        for (i = 0; i < count; ++i)
            if (strcmp(active[i]->site_id, c->site_id) == 0) goto invalid;
        active[count++] = c;
    }
    if (count == 0) return OK;
    if (!yz_cc_initialize()) goto invalid;
    /* Retain the same site's counters across graceful reconfiguration. New
     * sites reuse only fully refill-idle slots absent from the new inventory;
     * the old generation checks the identity under the same mutex and cannot
     * mistake the replacement site's empty table for its own allowance. */
    for (i = 0; i < count; ++i) {
        for (j = 0; j < YZ_CC_STATE_SITES; ++j) {
            yz_cc_site_state *state = &yz_cc_memory->sites[j];
            if (atomic_load_explicit(&state->valid, memory_order_acquire) && strcmp(state->site_id, active[i]->site_id) == 0) {
                active[i]->state = state;
                break;
            }
        }
    }
    for (i = 0; i < count; ++i) {
        if (active[i]->state) continue;
        for (j = 0; j < YZ_CC_STATE_SITES; ++j) {
            yz_cc_site_state *state = &yz_cc_memory->sites[j];
            size_t k;
            uint64_t now;
            int reserved = 0;
            for (k = 0; k < count; ++k)
                if (state == active[k]->state) reserved = 1;
            if (reserved) continue;
            if (!yz_cc_lock(&state->mutex)) goto invalid;
            if (!yz_cc_clock(&now) || !yz_cc_idle(state, now)) {
                (void)pthread_mutex_unlock(&state->mutex);
                continue;
            }
            atomic_store_explicit(&state->valid, 0, memory_order_release);
            memset(state->rows, 0, sizeof(state->rows));
            for (k = 0; k < YZ_CC_ROWS; ++k) atomic_init(&state->rows[k].active, 0);
            memcpy(state->site_id, active[i]->site_id, sizeof(state->site_id));
            atomic_store_explicit(&state->valid, 1, memory_order_release);
            active[i]->state = state;
            if (pthread_mutex_unlock(&state->mutex) != 0) goto invalid;
            break;
        }
        if (!active[i]->state) goto invalid;
    }
    return OK;
invalid:
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server,
                 "Yunzhan CC fixed inventory or shared admission state could not be verified");
    return HTTP_INTERNAL_SERVER_ERROR;
}

static request_rec *yz_cc_root(request_rec *r)
{
    unsigned int depth = 0;
    while (r && (r->main || r->prev)) {
        if (++depth > 64) return NULL;
        r = r->main ? r->main : r->prev;
    }
    return r;
}

/* Apache normalizes/unescapes parsed_uri.path before translate_name. Capture
 * it before mod_rewrite can change it, then charge the external request once
 * across DirectoryIndex subrequests, ErrorDocument and internal rewrites. */
static int yz_cc_capture(request_rec *r)
{
    yz_cc_config *c = ap_get_module_config(r->server->module_config, &yunzhan_cc_module);
    yz_cc_request *request;
    if (r->main || r->prev) return DECLINED;
    request = ap_get_module_config(r->request_config, &yunzhan_cc_module);
    if (!request) {
        request = apr_pcalloc(r->pool, sizeof(*request));
        ap_set_module_config(r->request_config, &yunzhan_cc_module, request);
    }
    if (!request->path && r->parsed_uri.path && strlen(r->parsed_uri.path) <= 8192)
        request->path = apr_pstrdup(r->pool, r->parsed_uri.path);
    if (c && c->site_id[0]) {
        apr_table_setn(r->err_headers_out, "X-Panel-Apache-CC", apr_pstrcat(r->pool, YZ_CC_ENGINE ":", c->fingerprint, NULL));
        /* The owned integrity route returns an EMPTY response before rewrite
         * or an application handler. It never forwards a whitelisted request
         * to a site. Root can still verify/disarm a full table without taking
         * any visitor's allowance. GET/POST, query variants, other paths and
         * forwarded external clients do not acquire this exemption. */
        if (request->path && strcmp(request->path, "/__yunzhan_waf_probe") == 0 &&
            strcmp(r->method, "HEAD") == 0 && r->args == NULL &&
            r->useragent_ip && strcmp(r->useragent_ip, "127.0.0.1") == 0 &&
            r->connection->client_ip && strcmp(r->connection->client_ip, "127.0.0.1") == 0) {
            int ready = c->off;
            if (!ready && yz_cc_memory && c->state && yz_cc_lock(&c->state->mutex)) {
                ready = atomic_load_explicit(&c->state->valid, memory_order_acquire) && strcmp(c->state->site_id, c->site_id) == 0;
                if (pthread_mutex_unlock(&c->state->mutex) != 0) ready = 0;
            }
            apr_table_setn(r->err_headers_out, "Cache-Control", "no-store");
            if (!ready) return HTTP_SERVICE_UNAVAILABLE;
            apr_table_setn(r->err_headers_out, "X-Panel-Apache-CC-Probe", YZ_CC_ENGINE);
            return HTTP_NO_CONTENT;
        }
    }
    return DECLINED;
}

static int yz_cc_key(const yz_cc_config *config, const yz_cc_rule *rule,
                      const unsigned char client[16], yz_cc_zone *zone)
{
    unsigned char input[89];
    unsigned int size = 0;
    memset(input, 0, sizeof(input));
    input[0] = rule ? 1 : 0;
    memcpy(input + 1, config->site_id, 32);
    if (rule) memcpy(input + 33, rule->id, 32);
    zone->rate = rule ? rule->rate : config->rate;
    zone->burst = rule ? rule->burst : config->burst;
    memcpy(input + 65, &zone->rate, 4);
    memcpy(input + 69, &zone->burst, 4);
    memcpy(input + 73, client, 16);
    return HMAC(EVP_sha256(), yz_cc_memory->secret, sizeof(yz_cc_memory->secret),
                input, sizeof(input), zone->key, &size) != NULL && size == sizeof(zone->key);
}

static void yz_cc_event(request_rec *r, const yz_cc_request *request)
{
    if (!request || !request->reason) return;
    apr_table_setn(r->subprocess_env, "PANEL_AW_SITE", request->site_id);
    apr_table_setn(r->subprocess_env, "PANEL_AW_REASON", request->reason);
    apr_table_setn(r->subprocess_env, "PANEL_AW_ACTION", request->observe ? "observe" : "block");
}

static int yz_cc_check(request_rec *r)
{
    yz_cc_config *c = ap_get_module_config(r->server->module_config, &yunzhan_cc_module);
    request_rec *root;
    yz_cc_request *request;
    yz_cc_zone zones[YZ_CC_MAX_ZONES];
    unsigned char client[16] = {0};
    size_t count = 1, i;
    uint64_t now, retry_ns;
    int decision = -1;
    const char *allow;
    if (!c || !c->site_id[0]) return DECLINED;
    apr_table_setn(r->err_headers_out, "X-Panel-Apache-CC", apr_pstrcat(r->pool, YZ_CC_ENGINE ":", c->fingerprint, NULL));
    if (c->off) return DECLINED;
    root = yz_cc_root(r);
    request = root ? ap_get_module_config(root->request_config, &yunzhan_cc_module) : NULL;
    if (!root) return c->observe ? DECLINED : HTTP_SERVICE_UNAVAILABLE;
    if (!request) {
        request = apr_pcalloc(root->pool, sizeof(*request));
        ap_set_module_config(root->request_config, &yunzhan_cc_module, request);
    }
    if (request->charged) { yz_cc_event(r, request); return request->result; }
    request->charged = 1;
    request->site_id = c->site_id;
    request->observe = c->observe;
    request->result = DECLINED;
    if (!request->path) goto unavailable;
    allow = apr_table_get(r->subprocess_env, "PANEL_AW_ALLOW");
    if (allow && strcmp(allow, "1") == 0) return DECLINED;
    if (!yz_cc_memory || !c->state || !r->useragent_ip) goto unavailable;
    if (inet_pton(AF_INET, r->useragent_ip, client + 12) == 1) {
        client[10] = client[11] = 255;
    } else if (inet_pton(AF_INET6, r->useragent_ip, client) != 1) goto unavailable;
    if (!yz_cc_key(c, NULL, client, &zones[0])) goto unavailable;
    for (i = 0; i < c->rule_count; ++i) {
        const yz_cc_rule *rule = &c->rules[i];
        if (strncmp(request->path, rule->path, rule->length) ||
            (!rule->prefix && request->path[rule->length] != '\0')) continue;
        if (!yz_cc_key(c, rule, client, &zones[count++])) goto unavailable;
    }
    if (!yz_cc_clock(&now) || !yz_cc_lock(&c->state->mutex)) goto unavailable;
    if (atomic_load_explicit(&c->state->valid, memory_order_acquire) && strcmp(c->state->site_id, c->site_id) == 0)
        decision = yz_cc_admit(c->state->rows, zones, count, now, &retry_ns);
    if (pthread_mutex_unlock(&c->state->mutex) != 0) goto unavailable;
    if (decision > 0) return DECLINED;
    if (decision == 0) {
        request->reason = "cc";
        request->result = c->observe ? DECLINED : HTTP_TOO_MANY_REQUESTS;
    } else {
        request->reason = "cc-capacity";
        request->result = c->observe ? DECLINED : HTTP_SERVICE_UNAVAILABLE;
    }
    goto reported;
unavailable:
    request->reason = "cc-unavailable";
    request->result = c->observe ? DECLINED : HTTP_SERVICE_UNAVAILABLE;
reported:
    yz_cc_event(root, request);
    yz_cc_event(r, request);
    if (!c->observe) {
        apr_table_setn(r->err_headers_out, "Retry-After", "1");
        apr_table_setn(r->err_headers_out, "Cache-Control", "no-store");
    }
    return request->result;
}

typedef struct { char data[YZ_CC_LOG_LINE]; size_t used; int bad; } yz_cc_json;

static void yz_cc_json_literal(yz_cc_json *out, const char *text)
{
    size_t length = strlen(text);
    if (length > sizeof(out->data) - out->used) { out->bad = 1; return; }
    memcpy(out->data + out->used, text, length);
    out->used += length;
}

/* Path bytes beyond the ASCII range are percent-encoded, preserving their
 * exact URI representation even for an invalid UTF-8 request. No query,
 * cookie, User-Agent, authorization header or request body enters the sink. */
static void yz_cc_json_string(yz_cc_json *out, const char *text, size_t limit, int path)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t i;
    yz_cc_json_literal(out, "\"");
    if (!text) text = "";
    for (i = 0; i < limit && text[i]; ++i) {
        unsigned char c = (unsigned char)text[i];
        char encoded[7] = {0};
        if (path && c >= 128) {
            encoded[0] = '%'; encoded[1] = hex[c >> 4]; encoded[2] = hex[c & 15];
        } else if (c == '"' || c == '\\') {
            encoded[0] = '\\'; encoded[1] = (char)c;
        } else if (c < 32 || c >= 127) {
            memcpy(encoded, "\\u00", 4); encoded[4] = hex[c >> 4]; encoded[5] = hex[c & 15];
        } else encoded[0] = (char)c;
        yz_cc_json_literal(out, encoded);
    }
    yz_cc_json_literal(out, "\"");
}

static int yz_cc_write_event(request_rec *r, request_rec *root, yz_cc_request *request)
{
    yz_cc_json out = {{0}, 0, 0};
    char numeric[128];
    apr_time_t timestamp = apr_time_now();
    int status = r->status >= 100 && r->status <= 599 ? r->status : 500;
    const char *path = request->path ? request->path : "";
    (void)snprintf(numeric, sizeof(numeric), "{\"epoch\":%lld,\"epoch_us\":%lld,\"status\":%d,", (long long)(timestamp / APR_USEC_PER_SEC), (long long)timestamp, status);
    yz_cc_json_literal(&out, numeric);
    yz_cc_json_literal(&out, "\"site_id\":"); yz_cc_json_string(&out, request->site_id, 32, 0);
    yz_cc_json_literal(&out, ",\"site\":"); yz_cc_json_string(&out, root->server->server_hostname, 253, 0);
    yz_cc_json_literal(&out, ",\"ip\":"); yz_cc_json_string(&out, root->useragent_ip, 46, 0);
    yz_cc_json_literal(&out, ",\"peer\":"); yz_cc_json_string(&out, root->connection->client_ip, 46, 0);
    yz_cc_json_literal(&out, ",\"method\":"); yz_cc_json_string(&out, root->method, 32, 0);
    yz_cc_json_literal(&out, ",\"path\":"); yz_cc_json_string(&out, path, 512, 1);
    if (strlen(path) > 512) yz_cc_json_literal(&out, ",\"path_truncated\":true");
    yz_cc_json_literal(&out, ",\"reason\":"); yz_cc_json_string(&out, request->reason, 32, 0);
    yz_cc_json_literal(&out, request->observe ? ",\"action\":\"observe\"}\n" : ",\"action\":\"block\"}\n");
    if (out.bad) return 0;
    return yz_cc_log_append(YZ_CC_LOG_PATH, out.data, out.used);
}

static int yz_cc_log(request_rec *r)
{
    request_rec *root = yz_cc_root(r);
    yz_cc_request *request = root ? ap_get_module_config(root->request_config, &yunzhan_cc_module) : NULL;
    if (request && request->reason) {
        if (!request->logged) {
            request->logged = 1; /* one best-effort attempt, never replay an unknown append */
            (void)yz_cc_write_event(r, root, request);
        }
        /* The ordinary Apache metadata CustomLog remains the legacy metadata
         * sink. CC uses only its independent bounded private file, and cannot
         * grow the old unbounded file through a second logger. */
        apr_table_unset(root->subprocess_env, "PANEL_AW_REASON");
        apr_table_unset(r->subprocess_env, "PANEL_AW_REASON");
    }
    return DECLINED;
}

static const command_rec yz_cc_commands[] = {
    AP_INIT_TAKE_ARGV("YunzhanCCSite", yz_cc_set_site, NULL, RSRC_CONF, "Closed per-site native CC policy"),
    AP_INIT_TAKE_ARGV("YunzhanCCRule", yz_cc_set_rule, NULL, RSRC_CONF, "Closed literal URL admission rule"),
    {NULL}
};

static void yz_cc_hooks(apr_pool_t *pool)
{
    static const char *const before_rewrite[] = {"mod_rewrite.c", NULL};
    (void)pool;
    ap_hook_post_config(yz_cc_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_translate_name(yz_cc_capture, NULL, before_rewrite, APR_HOOK_REALLY_FIRST);
    ap_hook_check_access(yz_cc_check, NULL, NULL, APR_HOOK_FIRST, AP_AUTH_INTERNAL_PER_URI);
    ap_hook_log_transaction(yz_cc_log, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA yunzhan_cc_module = {
    STANDARD20_MODULE_STUFF,
    NULL, NULL, yz_cc_create, NULL, yz_cc_commands, yz_cc_hooks,
    AP_MODULE_FLAG_NONE
};
