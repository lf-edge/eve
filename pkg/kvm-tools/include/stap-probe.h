#include "config.h"
#if ENABLE_SDT_PROBES
#include "sys/sdt.h"
#define PROBE(provider,probe) \
   STAP_PROBE(provider,probe)
#define PROBE1(provider,probe,x1) \
   STAP_PROBE1(provider,probe,x1)
#define PROBE2(provider,probe,x1,x2) \
   STAP_PROBE2(provider,probe,x1,x2)
#define PROBE3(provider,probe,x1,x2,x3) \
   STAP_PROBE3(provider,probe,x1,x2,x3)
#define PROBE4(provider,probe,x1,x2,x3,x4) \
   STAP_PROBE4(provider,probe,x1,x2,x3,x4)
#define PROBE5(provider,probe,x1,x2,x3,x4,x5) \
   STAP_PROBE5(provider,probe,x1,x2,x3,x4,x5)
#define PROBE6(provider,probe,x1,x2,x3,x4,x5,x6) \
   STAP_PROBE6(provider,probe,x1,x2,x3,x4,x5,x6)
#define PROBE7(provider,probe,x1,x2,x3,x4,x5,x6,x7) \
   STAP_PROBE7(provider,probe,x1,x2,x3,x4,x5,x6,x7)
#define PROBE8(provider,probe,x1,x2,x3,x4,x5,x6,x7,x8) \
   STAP_PROBE8(provider,probe,x1,x2,x3,x4,x5,x6,x7,x8)
#define PROBE9(provider,probe,x1,x2,x3,x4,x5,x6,x7,x8,x9) \
   STAP_PROBE9(provider,probe,x1,x2,x3,x4,x5,x6,x7,x8,x9)
#define PROBE10(provider,probe,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10) \
   STAP_PROBE10(provider,probe,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10)
#else
#define PROBE(provider,probe)
#define PROBE1(provider,probe,x1)
#define PROBE2(provider,probe,x1,x2)
#define PROBE3(provider,probe,x1,x2,x3)
#define PROBE4(provider,probe,x1,x2,x3,x4)
#define PROBE5(provider,probe,x1,x2,x3,x4,x5)
#define PROBE6(provider,probe,x1,x2,x3,x4,x5,x6)
#define PROBE7(provider,probe,x1,x2,x3,x4,x5,x6,x7)
#define PROBE8(provider,probe,x1,x2,x3,x4,x5,x6,x7,x8)
#define PROBE9(provider,probe,x1,x2,x3,x4,x5,x6,x7,x8,x9)
#define PROBE10(provider,probe,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10)
#endif

