#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#if defined(_WIN32) || defined(__CYGWIN__)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#else
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include "duktape.h"
#include "threadpool.h"

#include "nsProxyAutoConfig.h"

#define UTIL_BUFLEN 64

int util_dns_resolve(const char *host, char *buf, size_t buflen, int all);
int util_my_ip_address(char *buf, size_t buflen, int all);

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

#ifndef	INADDR_NONE
#define	INADDR_NONE 0xffffffff
#endif
#ifndef	IN_MULTICAST
#define	IN_MULTICAST(i) (((u_int32_t)(i) & 0xf0000000) == 0xe0000000)
#endif

static struct addrinfo *util_getaddrinfo(const char *node, const char *serv,
                                         int flags)
{
    struct addrinfo hints, *result;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = flags;

    int ret = getaddrinfo(node, serv, &hints, &result);
    if (ret) {
        logw("getaddrinfo() failed: %s\n", gai_strerror(ret));
        return NULL;
    }

    return result;
}

static int util_inet_ntop(int family, struct sockaddr *sa, char *buf,
                          size_t blen)
{
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
#if defined(_WIN32) || defined (__CYGWIN__)
    void *src;
#else
    const void *src;
#endif

    if (family == AF_INET) {
        sin = (struct sockaddr_in *)sa;
        src = &sin->sin_addr;
    } else if (family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *)sa;
        src = &sin6->sin6_addr;
    } else {
        logw("invalid address family %d\n", family);
        return -1;
    }

    if (!inet_ntop(family, src, buf, blen)) {
        perror("inet_ntop");
        return -1;
    }

    return 0;
}

int util_my_ip_address(char *buf, size_t buflen, int all)
{
    int ret = -1;
    char tmp[INET6_ADDRSTRLEN + 1];
#if defined(_WIN32) || defined(__CYGWIN__)
    PIP_ADAPTER_ADDRESSES pAdapterAddresses = NULL, pInfo = NULL;
    ULONG ulBufferLength = 0;
    DWORD dwRet;
    PIP_ADAPTER_UNICAST_ADDRESS pUniAddr;

    buf[0] = '\0';

    do {
        dwRet = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL,
                                     pAdapterAddresses, &ulBufferLength);
        if (dwRet == ERROR_BUFFER_OVERFLOW) {
            if (pAdapterAddresses)
                free(pAdapterAddresses);
            pAdapterAddresses = malloc(ulBufferLength);
            if (!pAdapterAddresses) {
                return -1;
            }
        }
    } while (dwRet == ERROR_BUFFER_OVERFLOW);

    if (dwRet != ERROR_SUCCESS && dwRet != ERROR_NO_DATA) {
        if (pAdapterAddresses)
            free(pAdapterAddresses);
        return -1;
    }

    int break_out = 0;
    for (pInfo = pAdapterAddresses; pInfo; pInfo = pInfo->Next) {
        for (pUniAddr = pInfo->FirstUnicastAddress; pUniAddr;
             pUniAddr = pUniAddr->Next) {
            DWORD dwLen = sizeof(tmp);
            int rc = WSAAddressToString(pUniAddr->Address.lpSockaddr,
                                        pUniAddr->Address.iSockaddrLength,
                                        NULL, (LPTSTR)tmp, &dwLen);
            if (rc)
                continue;

            char *percent = strchr(tmp, '%');
            if (percent)
                *percent = '\0';

            /* First check if there's enough space in buf. */
            if (strlen(tmp) + strlen(buf) + 2 > buflen) {
                /* Buffer too small. Try next address and see if it fits. */
                continue;
            }

            /* There's enough space to hold the address plus the semicolon. */
            if (strlen(buf) > 0)
                strcat(buf, ";");
            strcat(buf, tmp);

            ret = 0;

            if (!all) {
                break_out = 1;
                break;
            }
        }

        if (break_out)
            break;
    }

    free(pAdapterAddresses);
#else
    struct ifaddrs *addrs, *a;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
    uint32_t x;

    buf[0] = '\0';

    if (getifaddrs(&addrs)) {
        perror("getifaddrs() failed");
        return -1;
    }

    for (a = addrs; a; a = a->ifa_next) {
        if (!a->ifa_addr)
            continue;

        if (a->ifa_addr->sa_family == AF_INET) {
            sin = (struct sockaddr_in *)a->ifa_addr;
            x = ntohl(sin->sin_addr.s_addr);
            if (IN_MULTICAST(x) ||
                INADDR_ANY == x ||
                INADDR_NONE == x ||
                ((x & 0xff000000) == 0x7f000000) ||
                (((x & 0xff000000) == 0xa9000000) &&
                 ((x & 0x00ff0000) == 0x00fe0000))) {
                continue;
            }

            if (util_inet_ntop(sin->sin_family, a->ifa_addr, tmp,
                               sizeof(tmp))) {
                break;
            }
        } else if (a->ifa_addr->sa_family == AF_INET6) {
            sin6 = (struct sockaddr_in6 *)a->ifa_addr;
            if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) ||
                IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) ||
                IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
                IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr) ||
                IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) {
                continue;
            }

            if (util_inet_ntop(sin6->sin6_family, a->ifa_addr, tmp,
                               sizeof(tmp))) {
                break;
            }
        } else {
            continue;
        }

        if (strlen(tmp) + strlen(buf) + 2 > buflen)
            break;

        if (buf[0] != '\0')
            strcat(buf, ";");
        strcat(buf, tmp);

        ret = 0;

        if (!all)
            break;
    }

    if (addrs)
        freeifaddrs(addrs);
#endif

    return ret;
}

int util_dns_resolve(const char *host, char *buf, size_t buflen, int all)
{
    int ret = -1;
    char tmp[INET6_ADDRSTRLEN + 1];
    struct addrinfo *addrs = util_getaddrinfo(host, NULL, 0), *a;

    buf[0] = '\0';

    if (!addrs)
        goto out;

    for (a = addrs; a; a = a->ai_next) {
        if (util_inet_ntop(a->ai_family, a->ai_addr, tmp, sizeof(tmp))) {
            perror("inet_ntop");
            goto out;
        }

        if (strlen(tmp) + strlen(buf) + 2 > buflen)
            break;

        if (buf[0] != '\0')
            strcat(buf, ";");
        strcat(buf, tmp);

        ret = 0;

        if (!all)
            break;
    }

out:
    if (addrs)
        freeaddrinfo(addrs);
    return ret;
}
