/* uIP's configuration for this build: that of the project's unix port, with fewer connections,
   the declaration of `printf` that its main loop leaves out, and the one function of the C
   library its web server needs and SDCC lacks. */
#ifndef __UIP_CONF_H__
#define __UIP_CONF_H__

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

typedef uint8_t u8_t;
typedef uint16_t u16_t;
typedef unsigned short uip_stats_t;

#define UIP_CONF_MAX_CONNECTIONS 8
#define UIP_CONF_MAX_LISTENPORTS 4
#define UIP_CONF_BUFFER_SIZE     420
#define UIP_CONF_BYTE_ORDER      LITTLE_ENDIAN
#define UIP_CONF_LOGGING         1
#define UIP_CONF_UDP             0
#define UIP_CONF_UDP_CHECKSUMS   1
#define UIP_CONF_STATISTICS      1

int snprintf(char *buffer, size_t size, const char *format, ...);

#include "webserver.h"

#endif /* __UIP_CONF_H__ */
