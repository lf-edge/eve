struct pac;

struct pac *pac_init(char *js, int n_threads, void (*notify_cb)(void *),
                     void *arg);
int pac_find_proxy(struct pac *pac, char *url, char *host,
                   void (*cb)(char *_result, void *_arg), void *arg);
int pac_find_proxy_sync(char *js, char *url, char *host, char **proxy);
void pac_run_callbacks(struct pac *pac);

#define PAC_LOGLVL_DEBUG 0x00
#define PAC_LOGLVL_INFO  0x01
#define PAC_LOGLVL_WARN  0x02

typedef void (*log_fn_type)(int, const char *);
void pac_set_log_fn(log_fn_type fn);
