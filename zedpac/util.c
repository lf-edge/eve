#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
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

#include "util.h"

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
        fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(ret));
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
        fprintf(stderr, "invalid address family %d\n", family);
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

