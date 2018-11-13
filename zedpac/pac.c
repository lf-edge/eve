#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#if defined(_WIN32) || defined(__CYGWIN__)
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include "duktape.h"
#include "threadpool.h"

#include "nsProxyAutoConfig.h"
#include "util.h"

#include "pac.h"

/*
 * There are external PAC functions with multiple versions: a "plain" one,
 * returning only one result (e.g. dnsResolve() only returning one IP
 * address, such as "1.2.3.4"), and an *_ex version, returning optionally
 * multiple results, concanated via a ';', such as "1.2.3.4;5.6.7.8".
 */
#define RETURN_SINGLE_RESULT 0
#define RETURN_ALL_RESULTS 1

struct pac {
    char *javascript; /* JavaScript PAC code. */
    threadpool_t *threadpool;
    pthread_mutex_t ctx_mtx;
    int n_ctx;
    duk_context **ctx;
};

struct proxy_args {
    struct pac *pac;
    char *url;
    char *host;
    void (*cb)(char *, void *);
    char *result;
    void *arg;
};

/*
 * Pluggable logger function. The user can override the default one via
 * pac_set_log_fn().
 */
static void default_log_fn(int level, const char *buf)
{
    if (level == PAC_LOGLVL_WARN)
        fprintf(stderr, "[PAC] %s\n", buf);
}

static log_fn_type log_fn = default_log_fn;

void pac_set_log_fn(log_fn_type fn)
{
    log_fn = fn;
}

#ifdef __GNUC__
#define LOG_ATTR __attribute__((format(printf, 2, 3)))
#else
#define LOG_ATTR
#endif

static void _pac_log(int level, const char *fmt, ...) LOG_ATTR;

static void _pac_log(int level, const char *fmt, ...)
{
    va_list args;
    char buf[1024];

    if (!log_fn)
        return;

    va_start(args,fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    log_fn(level, buf);
}

#define logw(...) do { \
    _pac_log(PAC_LOGLVL_WARN, __VA_ARGS__); \
} while(0)
#define logi(fmt, ...) do { \
    _pac_log(PAC_LOGLVL_INFO, __VA_ARGS__); \
} while(0)
#define logd(fmt, ...) do { \
    _pac_log(PAC_LOGLVL_DEBUG, __VA_ARGS__); \
} while(0)

static void fatal_handler(void *udata, const char *msg)
{
    logw("Fatal error: %s (%p).", msg, udata);
}

/*
 * Note: error handling in these function is not standardized. The best
 * documentation available is:
 *
 * https://msdn.microsoft.com/en-us/library/windows/desktop/gg308477(v=vs.85).aspx
 *
 * which states that (at least for the *Ex versions) the function should
 * return an empty string if an error occurs (and not throw an error).
 */
static int _dns_resolve(duk_context *ctx, int all_results)
{
    char buf[UTIL_BUFLEN];
    const char *host = duk_require_string(ctx, 0);

    if (util_dns_resolve(host, buf, sizeof(buf), all_results) < 0)
        buf[0] = '\0';

    duk_push_string(ctx, buf);
    return 1;
}

static int dns_resolve(duk_context *ctx)
{
    return _dns_resolve(ctx, RETURN_SINGLE_RESULT);
}

static int dns_resolve_ex(duk_context *ctx)
{
    return _dns_resolve(ctx, RETURN_ALL_RESULTS);
}

static int _my_ip_address(duk_context *ctx, int all_results)
{
    char buf[UTIL_BUFLEN];

    if (util_my_ip_address(buf, sizeof(buf), all_results) < 0)
        buf[0] = '\0';

    duk_push_string(ctx, buf);
    return 1;
}

static int my_ip_address(duk_context *ctx)
{
    return _my_ip_address(ctx, RETURN_SINGLE_RESULT);
}

static int my_ip_address_ex(duk_context *ctx)
{
    return _my_ip_address(ctx, RETURN_ALL_RESULTS);
}

static void *alloc_ctx(char *js)
{
    duk_context *ctx;

    ctx = duk_create_heap(NULL, NULL, NULL, NULL, fatal_handler);
    if (!ctx)
        return ctx;

    duk_push_global_object(ctx);
    duk_push_c_function(ctx, dns_resolve, 1 /*nargs*/);
    duk_put_prop_string(ctx, -2, "dnsResolve");
    duk_push_c_function(ctx, my_ip_address, 0 /*nargs*/);
    duk_put_prop_string(ctx, -2, "myIpAddress");
    duk_push_c_function(ctx, dns_resolve_ex, 1 /*nargs*/);
    duk_put_prop_string(ctx, -2, "dnsResolveEx");
    duk_push_c_function(ctx, my_ip_address_ex, 0 /*nargs*/);
    duk_put_prop_string(ctx, -2, "myIpAddressEx");
    duk_pop(ctx);

    duk_eval_string(ctx, nsProxyAutoConfig);
    duk_pop(ctx);

    duk_eval_string(ctx, nsProxyAutoConfig0);
    duk_pop(ctx);

    /* Try to evaluate our Javascript PAC file. */
    if (duk_peval_string(ctx, js) != 0) {
        logw("Failed to evaluate PAC file: %s.", duk_safe_to_string(ctx, -1));
        duk_pop(ctx);
        duk_destroy_heap(ctx);
        errno = EINVAL;
        return NULL;
    }
    duk_pop(ctx);

    return ctx;
}

static char *find_proxy(duk_context *ctx, char *url, char *host)
{
    char *result = NULL;
    const char *proxy;

    duk_push_global_object(ctx);
    duk_get_prop_string(ctx, -1 /*index*/, "FindProxyForURL");
    duk_push_string(ctx, url);
    duk_push_string(ctx, host);

    if (duk_pcall(ctx, 2 /*nargs*/) == DUK_EXEC_SUCCESS) {
        proxy = duk_to_string(ctx, -1);
        if (!proxy)
            logw("Failed to allocate proxy string.");
        else
            result = strdup(proxy);
    } else {
        if (duk_is_error(ctx, -1)) {
            /*
             * Accessing .stack might cause an error to be thrown, so
             * wrap this access in a duk_safe_call() if it matters.
             */
            duk_get_prop_string(ctx, -1, "stack");
            logw("Javascript call failed: %s.", duk_safe_to_string(ctx, -1));
            duk_pop(ctx); /* Result string. */
        } else {
            /* Non-Error value, coerce safely to string. */
            logw("Javascript call failed: %s.", duk_safe_to_string(ctx, -1));
        }
    }

    duk_pop(ctx); /* Result string. */
    duk_pop(ctx); /* Global object. */

    return result;
}

static void main_result(void *arg)
{
    struct proxy_args *pa = arg;

    if (pa->host != NULL) {
        logw("Assertion error: pa->host == %p", pa->host);
    }
    if (pa->url != NULL) {
        logw("Assertion error: pa->url == %p", pa->url);
    }

    pa->cb(pa->result, pa->arg);

    free(pa);
}

static duk_context *pop_context(struct pac *pac)
{
    int i;

    pthread_mutex_lock(&pac->ctx_mtx);

    for (i = 0; i < pac->n_ctx; i++) {
        if (pac->ctx[i] != NULL) {
            duk_context *ctx = pac->ctx[i];
            pac->ctx[i] = NULL;
            pthread_mutex_unlock(&pac->ctx_mtx);
            return ctx;
        }
    }

    pthread_mutex_unlock(&pac->ctx_mtx);

    assert(0);
}

static void push_context(struct pac *pac, duk_context *ctx)
{
    int i;

    pthread_mutex_lock(&pac->ctx_mtx);

    for (i = 0; i < pac->n_ctx; i++) {
        if (pac->ctx[i] == NULL) {
            pac->ctx[i] = ctx;
            pthread_mutex_unlock(&pac->ctx_mtx);
            return;
        }
    }

    pthread_mutex_unlock(&pac->ctx_mtx);

    assert(0);
}

static void _pac_find_proxy(void *arg)
{
    struct proxy_args *pa = arg;
    struct pac *pac = pa->pac;
    duk_context *ctx = pop_context(pac);

    pa->result = find_proxy(ctx, pa->url, pa->host);

    free(pa->host);
    pa->host = NULL;
    free(pa->url);
    pa->url = NULL;

    push_context(pac, ctx);

    threadpool_schedule_back(pac->threadpool, main_result, pa);
}

int pac_find_proxy(struct pac *pac, char *url, char *host,
                   void (*cb)(char *_result, void *_arg), void *arg)
{
    struct proxy_args *pa = malloc(sizeof(struct proxy_args));

    if (!pa) {
        logw("Failed to allocate proxy arguments.");
        return -1;
    }

    pa->pac = pac;
    pa->url = strdup(url);
    pa->host = strdup(host);
    pa->arg = arg;
    pa->cb = cb;
    pa->result = NULL;

    if (!pa->url || !pa->host) {
        logw("Failed to allocate proxy arguments.");
        return -1;
    }

    if (threadpool_schedule(pac->threadpool, _pac_find_proxy, pa) < 0) {
        logw("Failed to schedule work item.");
        return -1;
    }

    return 0;
}

int pac_find_proxy_sync(char *js, char *url, char *host, char **proxy)
{
    duk_context *ctx = alloc_ctx(js);
    if (ctx) {
        *proxy = find_proxy(ctx, url, host);
        duk_destroy_heap(ctx);
        return 0;
    } else {
        logw("Failed to allocate JS context.");
        return -1;
    }
}

void pac_run_callbacks(struct pac *pac)
{
    threadpool_run_callbacks(pac->threadpool);
}

static int check_js(char *js)
{
    duk_context *ctx = alloc_ctx(js);
    if (!ctx)
        return -1;

    duk_destroy_heap(ctx);

    return 0;
}

struct pac *pac_init(char *js, int n_threads, void (*notify_cb)(void *),
                     void *arg)
{
    struct pac *pac = NULL;
    int i, ret = check_js(js);
    if (ret)
        goto err;

    ret = -1;

    pac = calloc(1, sizeof(struct pac));
    if (!pac) {
        logw("Error allocating PAC.");
        goto err;
    }

    pac->javascript = strdup(js);
    pac->n_ctx = n_threads; /* One context per worker thread. */
    pac->ctx = calloc(pac->n_ctx, sizeof(duk_context *));
    pac->threadpool = threadpool_create(n_threads, notify_cb, arg);
    if (!pac->javascript || !pac->ctx || !pac->threadpool) {
        logw("Error setting up PAC.");
        goto err;
    }

    for (i = 0; i < pac->n_ctx; i++) {
        pac->ctx[i] = alloc_ctx(js);
        if (!pac->ctx[i]) {
            logw("Error creating PAC context #%d.", i);
            goto err;
        }
    }

    if (pthread_mutex_init(&pac->ctx_mtx, NULL)) {
        logw("Error initializing mutex.");
        goto err;
    }

    return pac;

err:
    if (pac && pac->javascript)
        free(pac->javascript);
    if (pac && pac->ctx) {
        for (i = 0; i < n_threads; i++)
            if (pac->ctx[i])
                duk_destroy_heap(pac->ctx[i]);
        free(pac->ctx);
    }
    if (pac && pac->threadpool)
        threadpool_die(pac->threadpool, 1);
    if (pac)
        free(pac);
    return NULL;
}

void pac_free(struct pac *pac)
{
    free(pac->javascript);
    duk_destroy_heap(*pac->ctx);
    threadpool_die(pac->threadpool, 1);
    free(pac);
}
