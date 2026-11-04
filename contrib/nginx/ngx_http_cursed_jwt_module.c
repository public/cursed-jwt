/*
 * ngx_http_cursed_jwt_module: JWT verification in the access phase with cursed-jwt.
 *
 *   cursed_jwt          "realm" | off;    enable (realm goes into WWW-Authenticate)
 *   cursed_jwt_key_file file.jwks;        the first key of a JWKS: kty oct -> HS256, RSA -> RS256, EC P-256 -> ES256
 *   cursed_jwt_batch    N;                0/1 = verify inline; N > 1 = collect up to N requests per event-loop
 *                                         round and verify them in one cursed-jwt batch call (see below)
 *
 * The key fixes the algorithm: a token whose header "alg" differs is rejected (no alg confusion, no "none").
 * Accepted = cursed-jwt status JWT_OK or JWT_BAD_PAYLOAD (the latter: signature and time valid, but the
 * library's application claims sub/username are absent; an nginx gate does not need them).
 * Claim rules are cursed-jwt's: exp REQUIRED and > now, nbf <= now if present, strict RFC 8259 JSON;
 * iss/aud/iat are not checked.  contrib/nginx/README.md lists the differences from kjdev/nginx-auth-jwt.
 *
 * Batch mode: the access handler queues the request and returns NGX_AGAIN; the first request queued in a round
 * posts an event.  nginx runs posted events after it has processed every I/O event of the epoll_wait round, so
 * the batch holds all the requests that arrived together.  The posted handler verifies them in one call and
 * resumes each request's phases.  The queue is only ever flushed from that event, never inside a request's own
 * handler.  Requests freed or internally redirected meanwhile are handled through heap tickets (below).
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "jwt.h"

#define CJ_MAX_BATCH 64   /* largest batch handed to cursed-jwt */
#define CJ_QUEUE     1024 /* requests queued per event-loop round; beyond that, verify inline */

typedef struct {
    ngx_flag_t enabled; /* NGX_CONF_UNSET until merged */
    ngx_str_t realm;
    ngx_int_t kind; /* 0 none, 1 HS256, 2 PK */
    jwt_key_t *hkey;
    jwt_pkey_t *pkey;
    ngx_int_t batch;
} ngx_http_cursed_jwt_loc_conf_t;

typedef struct {
    ngx_uint_t state; /* 0 new, 1 queued, 2 done */
    ngx_int_t rc;     /* NGX_OK or 401 once done */
} ngx_http_cursed_jwt_ctx_t;

/* A queued request is reached through a heap ticket.  The request's pool cleanup owns a slot pointing back at
 * the ticket: freeing the request (client gone, an HTTP/2 connection torn down while its batch-mates are resumed)
 * clears ticket->r, and the flush clears the slot before freeing the ticket.  Neither side goes through the module
 * ctx, which an internal redirect (error_page, try_files) resets while the request runs. */
typedef struct {
    ngx_http_request_t *r;
    ngx_http_cursed_jwt_loc_conf_t *conf;
    ngx_http_cursed_jwt_ctx_t *ctx;
    void **slot; /* the pool cleanup's data */
} cj_ticket_t;

typedef struct {
    cj_ticket_t *t[CJ_QUEUE];
    ngx_uint_t n;
    ngx_event_t ev;
} ngx_http_cursed_jwt_queue_t;

static ngx_http_cursed_jwt_queue_t cj_queue; /* per worker process */

static ngx_int_t ngx_http_cursed_jwt_init(ngx_conf_t *cf);
static void *ngx_http_cursed_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_cursed_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_cursed_jwt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_cursed_jwt_key_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_http_cursed_jwt_flush(ngx_event_t *ev);

static ngx_command_t ngx_http_cursed_jwt_commands[] = {
    { ngx_string("cursed_jwt"), NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_cursed_jwt, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("cursed_jwt_key_file"), NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_cursed_jwt_key_file, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL },
    { ngx_string("cursed_jwt_batch"), NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http_cursed_jwt_loc_conf_t, batch), NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_cursed_jwt_module_ctx = { NULL,
                                                            ngx_http_cursed_jwt_init,
                                                            NULL,
                                                            NULL,
                                                            NULL,
                                                            NULL,
                                                            ngx_http_cursed_jwt_create_loc_conf,
                                                            ngx_http_cursed_jwt_merge_loc_conf };

ngx_module_t ngx_http_cursed_jwt_module = { NGX_MODULE_V1,
                                            &ngx_http_cursed_jwt_module_ctx,
                                            ngx_http_cursed_jwt_commands,
                                            NGX_HTTP_MODULE,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NGX_MODULE_V1_PADDING };


/* ---- verification ---- */

static void cj_verify(ngx_http_cursed_jwt_loc_conf_t *cf, int n, const char *const *tok, const int *len, uint8_t *ok) {
    jwt_result_t res[CJ_MAX_BATCH];
    int i;

    if (cf->kind == 1) {
        jwt_verify_batch(cf->hkey, n, tok, len, (int64_t)ngx_time(), res);
    } else {
        jwt_verify_batch_pk(cf->pkey, n, tok, len, (int64_t)ngx_time(), res);
    }
    for (i = 0; i < n; i++) { ok[i] = res[i].status == JWT_OK || res[i].status == JWT_BAD_PAYLOAD; }
}

/* The bytes after "Bearer " (scheme case-insensitive, as RFC 7235), or len 0. */
static void cj_token(ngx_http_request_t *r, const char **tok, int *len) {
    ngx_table_elt_t *h = r->headers_in.authorization;
    u_char *p, *end;

    *len = 0;
    if (h == NULL || h->value.len < sizeof("Bearer ") - 1 ||
        ngx_strncasecmp(h->value.data, (u_char *)"Bearer ", sizeof("Bearer ") - 1) != 0) {
        return;
    }
    p = h->value.data + sizeof("Bearer ") - 1;
    end = h->value.data + h->value.len;
    while (p < end && *p == ' ') { p++; }
    if (end - p > 0 && end - p <= JWT_TOKEN_MAX) {
        *tok = (const char *)p;
        *len = (int)(end - p);
    }
}

static ngx_int_t cj_unauthorized(ngx_http_request_t *r, ngx_http_cursed_jwt_loc_conf_t *cf) {
    ngx_table_elt_t *h;
    size_t n;
    u_char *p;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    n = sizeof("Bearer realm=\"\"") - 1 + cf->realm.len;
    p = ngx_pnalloc(r->pool, n);
    if (p == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    h->hash = 1;
    h->next = NULL;
    ngx_str_set(&h->key, "WWW-Authenticate");
    h->value.data = p;
    h->value.len = ngx_sprintf(p, "Bearer realm=\"%V\"", &cf->realm) - p;
    r->headers_out.www_authenticate = h;
    return NGX_HTTP_UNAUTHORIZED;
}


/* ---- batch queue ---- */

static void cj_cleanup(void *data) {
    cj_ticket_t *t = *(cj_ticket_t **)data;

    if (t != NULL) { t->r = NULL; }
}

/* Verify t[0..nt) (one key, nt <= CJ_MAX_BATCH) and record each live request's result. */
static void cj_verify_tickets(cj_ticket_t **t, ngx_uint_t nt) {
    const char *tok[CJ_MAX_BATCH];
    int len[CJ_MAX_BATCH];
    uint8_t ok[CJ_MAX_BATCH];
    ngx_uint_t i, k, n = 0;

    for (i = 0; i < nt; i++) {
        if (t[i]->r != NULL) {
            cj_token(t[i]->r, &tok[n], &len[n]); /* only requests with a token are queued */
            n++;
        }
    }
    if (n == 0) { return; }
    cj_verify(t[0]->conf, (int)n, tok, len, ok);
    for (i = 0, k = 0; i < nt; i++) {
        if (t[i]->r != NULL) {
            t[i]->ctx->state = 2;
            t[i]->ctx->rc = ok[k++] ? NGX_OK : NGX_HTTP_UNAUTHORIZED;
        }
    }
}

/* The posted event: runs after nginx has handled every I/O event of this epoll_wait round. */
static void ngx_http_cursed_jwt_flush(ngx_event_t *ev) {
    static cj_ticket_t *t[CJ_QUEUE];
    ngx_http_request_t *r;
    ngx_connection_t *c;
    ngx_uint_t i, j, nt;

    /* take the queue: requests resumed below may queue the next round (they post the event again) */
    nt = cj_queue.n;
    ngx_memcpy(t, cj_queue.t, nt * sizeof(t[0]));
    cj_queue.n = 0;

    /* runs of one key, at most that location's batch size each */
    for (i = 0; i < nt; i = j) {
        for (j = i + 1; j < nt && j - i < (ngx_uint_t)t[i]->conf->batch && t[j]->conf == t[i]->conf; j++) {
            /* extend the run */
        }
        cj_verify_tickets(t + i, j - i);
    }
    for (i = 0; i < nt; i++) {
        r = t[i]->r;
        if (r != NULL) {
            c = r->connection;
            r->write_event_handler(r);
            ngx_http_run_posted_requests(c);
        }
    }
    for (i = 0; i < nt; i++) {
        if (t[i]->r != NULL) {
            *t[i]->slot = NULL; /* the request lives on: its cleanup must not touch the freed ticket */
        }
        ngx_free(t[i]);
    }
}

/* NGX_AGAIN: queued for this round's batch.  NGX_DECLINED: the queue is full, verify inline. */
static ngx_int_t cj_enqueue(ngx_http_request_t *r, ngx_http_cursed_jwt_loc_conf_t *cf, ngx_http_cursed_jwt_ctx_t *ctx) {
    ngx_pool_cleanup_t *cln;
    cj_ticket_t *t;

    if (cj_queue.n == CJ_QUEUE) { return NGX_DECLINED; }
    cln = ngx_pool_cleanup_add(r->pool, sizeof(cj_ticket_t *));
    if (cln == NULL) { return NGX_ERROR; }
    t = ngx_alloc(sizeof(cj_ticket_t), r->connection->log);
    if (t == NULL) {
        *(cj_ticket_t **)cln->data = NULL;
        return NGX_ERROR;
    }
    t->r = r;
    t->conf = cf;
    t->ctx = ctx;
    t->slot = cln->data;
    *(cj_ticket_t **)cln->data = t;
    cln->handler = cj_cleanup;

    ctx->state = 1;
    cj_queue.t[cj_queue.n++] = t;
    r->write_event_handler = ngx_http_core_run_phases;
    if (!cj_queue.ev.posted) {
        cj_queue.ev.handler = ngx_http_cursed_jwt_flush;
        cj_queue.ev.log = ngx_cycle->log;
        ngx_post_event(&cj_queue.ev, &ngx_posted_events);
    }
    return NGX_AGAIN;
}


/* ---- access phase ---- */

static ngx_int_t ngx_http_cursed_jwt_handler(ngx_http_request_t *r) {
    ngx_http_cursed_jwt_loc_conf_t *cf;
    ngx_http_cursed_jwt_ctx_t *ctx;
    const char *tok;
    int len;
    uint8_t ok;
    ngx_int_t rc;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_cursed_jwt_module);
    if (!cf->enabled || cf->kind == 0) { return NGX_DECLINED; }

    ctx = ngx_http_get_module_ctx(r, ngx_http_cursed_jwt_module);
    if (ctx != NULL) {
        if (ctx->state == 2) { return ctx->rc == NGX_OK ? NGX_OK : cj_unauthorized(r, cf); }
        return NGX_AGAIN;
    }

    cj_token(r, &tok, &len);
    if (len == 0) { return cj_unauthorized(r, cf); }

    if (cf->batch > 1) {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) { return NGX_ERROR; }
        ngx_http_set_ctx(r, ctx, ngx_http_cursed_jwt_module);
        rc = cj_enqueue(r, cf, ctx);
        if (rc != NGX_DECLINED) { return rc; }
        ngx_http_set_ctx(r, NULL, ngx_http_cursed_jwt_module); /* queue full: verify inline */
    }

    cj_verify(cf, 1, &tok, &len, &ok);
    return ok ? NGX_OK : cj_unauthorized(r, cf);
}


/* ---- configuration ---- */

static void *ngx_http_cursed_jwt_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_cursed_jwt_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) { return NULL; }
    conf->enabled = NGX_CONF_UNSET;
    conf->kind = NGX_CONF_UNSET;
    conf->batch = NGX_CONF_UNSET;
    return conf;
}

static char *ngx_http_cursed_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_cursed_jwt_loc_conf_t *prev = parent, *conf = child;

    if (conf->enabled == NGX_CONF_UNSET) {
        conf->enabled = prev->enabled == NGX_CONF_UNSET ? 0 : prev->enabled;
        conf->realm = prev->realm;
    }
    if (conf->kind == NGX_CONF_UNSET) {
        conf->kind = prev->kind == NGX_CONF_UNSET ? 0 : prev->kind;
        conf->hkey = prev->hkey;
        conf->pkey = prev->pkey;
    }
    ngx_conf_merge_value(conf->batch, prev->batch, 0);
    if (conf->batch > CJ_MAX_BATCH) { conf->batch = CJ_MAX_BATCH; }
    if (conf->enabled && conf->kind == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "cursed_jwt is on but no cursed_jwt_key_file");
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *ngx_http_cursed_jwt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_cursed_jwt_loc_conf_t *lcf = conf;
    ngx_str_t *value = cf->args->elts;

    if (lcf->enabled != NGX_CONF_UNSET) { return "is duplicate"; }
    if (value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0) {
        lcf->enabled = 0;
        return NGX_CONF_OK;
    }
    lcf->enabled = 1;
    lcf->realm = value[1];
    return NGX_CONF_OK;
}

/* Config-time JWKS reading: the string value of "name" in the first object of "keys" (or the top object).
 * Deliberately small: no escapes in values (base64url and kty/crv names never have any). */
static ngx_int_t cj_json_str(u_char *p, u_char *end, const char *name, ngx_str_t *out) {
    size_t n = ngx_strlen(name);
    u_char *q, *obj_end;

    obj_end = ngx_strlchr(p, end, '}');
    if (obj_end == NULL) { return NGX_ERROR; }
    for (q = p; q + n + 2 < obj_end; q++) {
        if (q[0] == '"' && ngx_strncmp(q + 1, name, n) == 0 && q[n + 1] == '"') {
            q += n + 2;
            while (q < obj_end && (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n' || *q == ':')) { q++; }
            if (q >= obj_end || *q != '"') { return NGX_ERROR; }
            out->data = ++q;
            while (q < obj_end && *q != '"') { q++; }
            out->len = q - out->data;
            return NGX_OK;
        }
    }
    return NGX_DECLINED;
}

static ngx_int_t cj_b64(ngx_conf_t *cf, ngx_str_t *in, u_char **out, size_t *outlen) {
    int n;

    *out = ngx_pnalloc(cf->pool, in->len / 4 * 3 + 3 + 32);
    if (*out == NULL) { return NGX_ERROR; }
    n = jwt_b64url_decode(*out, (const char *)in->data, (int)in->len);
    if (n < 0) { return NGX_ERROR; }
    *outlen = n;
    return NGX_OK;
}

static char *ngx_http_cursed_jwt_key_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_cursed_jwt_loc_conf_t *lcf = conf;
    ngx_str_t *value = cf->args->elts, kty, a, b;
    ngx_file_t file;
    ngx_file_info_t fi;
    u_char *buf, *p, *end, *da, *db;
    size_t la, lb;
    ssize_t n;

    if (lcf->kind != NGX_CONF_UNSET) { return "is duplicate"; }
    if (ngx_conf_full_name(cf->cycle, &value[1], 1) != NGX_OK) { return NGX_CONF_ERROR; }
    ngx_memzero(&file, sizeof(file));
    file.name = value[1];
    file.log = cf->log;
    file.fd = ngx_open_file(value[1].data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE || ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        return "cannot open the key file";
    }
    buf = ngx_pnalloc(cf->pool, ngx_file_size(&fi) + 1);
    n = buf ? ngx_read_file(&file, buf, ngx_file_size(&fi), 0) : -1;
    ngx_close_file(file.fd);
    if (n != ngx_file_size(&fi)) { return "cannot read the key file"; }
    end = buf + n;
    p = ngx_strnstr(buf, "\"keys\"", n);
    p = ngx_strlchr(p ? p : buf, end, '{');
    if (p == NULL || cj_json_str(p, end, "kty", &kty) != NGX_OK) { return "no key (kty) in the key file"; }

    if (kty.len == 3 && ngx_strncmp(kty.data, "oct", 3) == 0) {
        if (cj_json_str(p, end, "k", &a) != NGX_OK || cj_b64(cf, &a, &da, &la) != NGX_OK) { return "bad oct key (k)"; }
        lcf->hkey = ngx_palloc(cf->pool, sizeof(jwt_key_t));
        if (lcf->hkey == NULL) { return NGX_CONF_ERROR; }
        jwt_key_init(lcf->hkey, da, la);
        lcf->kind = 1;
        return NGX_CONF_OK;
    }
    if (kty.len == 3 && ngx_strncmp(kty.data, "RSA", 3) == 0) {
        if (cj_json_str(p, end, "n", &a) != NGX_OK || cj_json_str(p, end, "e", &b) != NGX_OK ||
            cj_b64(cf, &a, &da, &la) != NGX_OK || cj_b64(cf, &b, &db, &lb) != NGX_OK) {
            return "bad RSA key (n, e)";
        }
        lcf->pkey = jwt_pkey_rs256(da, la, db, lb);
    } else if (kty.len == 2 && ngx_strncmp(kty.data, "EC", 2) == 0) {
        if (cj_json_str(p, end, "x", &a) != NGX_OK || cj_json_str(p, end, "y", &b) != NGX_OK ||
            cj_b64(cf, &a, &da, &la) != NGX_OK || cj_b64(cf, &b, &db, &lb) != NGX_OK || la != 32 || lb != 32) {
            return "bad EC P-256 key (x, y)";
        }
        lcf->pkey = jwt_pkey_es256(da, db);
    } else {
        return "unsupported kty (oct, RSA, EC P-256)";
    }
    if (lcf->pkey == NULL) { return "cursed-jwt refused the public key"; }
    lcf->kind = 2; /* jwt_pkey_t lives for the life of the process (config reloads leak it; prototype) */
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_cursed_jwt_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) { return NGX_ERROR; }
    *h = ngx_http_cursed_jwt_handler;
    return NGX_OK;
}
