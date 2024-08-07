#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
  #include <sys/param.h>
  #include <stdlib.h>
  #include <stdint.h>
  #include <sys/ioctl.h>
  #include <sys/socket.h>
  #include <net/if.h>
  #include <ifaddrs.h>
  #include <net/if_dl.h>

  uint8_t* lladdr(struct ifaddrs* ifap) {
    return (uint8_t *)LLADDR((struct sockaddr_dl *)(ifap)->ifa_addr);
  }
#endif
