#define UTIL_BUFLEN 64

int util_dns_resolve(const char *host, char *buf, size_t buflen, int all);
int util_my_ip_address(char *buf, size_t buflen, int all);
