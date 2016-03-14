#include <assert.h>//riot
// #include <ctype.h>
// #include <errno.h>
// #include <fcntl.h>
// #include <getopt.h>
// #include <stdarg.h>
#include <stdbool.h>//riot
#include <stdio.h>//riot
#include <stdlib.h>//riot
#include <string.h>//riot
#include <time.h>//riot
#include <unistd.h>//riot

#define FATAL   0 // FATAL		//riot
#define ERROR   1 // ERROR
#define WARNING 2 // WARNING
#define INFO    3 // INFO
#define DEBUG   4 // DEBUG
#define TRACE   5 // TRACE
#define VERBOSE 6 // VERBOSE

/*riot*/
#define DEBUGMSG(LVL, ...) do {       \
        if ((LVL)>debug_level) break;   \
        fprintf(stderr, __VA_ARGS__);   \
    } while (0)
# define DEBUGMSG_CORE(...) DEBUGMSG(__VA_ARGS__)
# define DEBUGMSG_CFWD(...) DEBUGMSG(__VA_ARGS__)
# define DEBUGMSG_CUTL(...) DEBUGMSG(__VA_ARGS__)
# define DEBUGMSG_PIOT(...) DEBUGMSG(__VA_ARGS__)

#define DEBUGSTMT(LVL, ...) do { \
        if ((LVL)>debug_level) break; \
        __VA_ARGS__; \
     } while (0)

#define TRACEIN(...)                    do {} while(0)
#define TRACEOUT(...)                   do {} while(0)

#define CONSTSTR(s)                     s

#define ccnl_malloc(s)                  malloc(s)
#define ccnl_calloc(n,s)                calloc(n,s)
#define ccnl_realloc(p,s)               realloc(p,s)
#define ccnl_free(p)                    free(p)

#define free_2ptr_list(a,b)     ccnl_free(a), ccnl_free(b)
#define free_3ptr_list(a,b,c)   ccnl_free(a), ccnl_free(b), ccnl_free(c)
#define free_4ptr_list(a,b,c,d) ccnl_free(a), ccnl_free(b), ccnl_free(c), ccnl_free(d);
#define free_5ptr_list(a,b,c,d,e) ccnl_free(a), ccnl_free(b), ccnl_free(c), ccnl_free(d), ccnl_free(e);

#define free_prefix(p)  do{ if(p) \
                free_5ptr_list(p->bytes,p->comp,p->complen,p->chunknum,p); } while(0)
#define free_content(c) do{ /* free_prefix(c->name); */ free_packet(c->pkt); \
                        ccnl_free(c); } while(0)

#define ccnl_frag_new(a,b)                      NULL
#define ccnl_frag_destroy(e)                    do {} while(0)

#define ccnl_sched_destroy(s)           do {} while(0)

#define ccnl_mgmt(r,b,p,f)              -1

#define ccnl_nfn_monitor(a,b,c,d,e)     do{}while(0)

#define ccnl_app_RX(x,y)                do{}while(0)

#define ccnl_close_socket(s)            close(s)

#define compute_ccnx_digest(b) NULL
#define local_producer(...)             0

#define SOCKADDR_MAX_DATA_LEN   (26)

typedef unsigned short sa_family_t;   /**< address family type */ //copy from RIOT socket.h
typedef uint16_t in_port_t;         /**< Internet port type */
typedef uint32_t in_addr_t;         /**< IPv4 address type */

/**
 * IPv4 address structure type.
 */
struct in_addr {
    in_addr_t s_addr;           /**< an IPv4 address */
};

/**
 * @brief   IPv6 address structure type.
 */
struct in6_addr {
    uint8_t s6_addr[16];        /**< unsigned 8-bit integer array */
};

/**
 * @brief   Used to define the socket address.
 */
struct sockaddr {
    sa_family_t sa_family;                  /**< Address family */
    char sa_data[SOCKADDR_MAX_DATA_LEN];    /**< Socket address (variable length data) */
};

/**
 * @brief   Implementation based socket address table.
 * @extends struct sockaddr
 */
struct sockaddr_storage {
    sa_family_t ss_family;                  /**< Address family */
    uint8_t ss_data[SOCKADDR_MAX_DATA_LEN]; /**< Socket address */
};
/**
 * @brief   IPv4 socket address type.
 * @extends struct sockaddr
 */
struct sockaddr_in {
    sa_family_t     sin_family; /**< Protocol family, always AF_INET */
    in_port_t       sin_port;   /**< Port number */
    struct in_addr  sin_addr;   /**< IPv4 address */
};

/**
 * IPv6 socket address type.
 * @extends struct sockaddr
 */
struct sockaddr_in6 {
    /**
     * Protocol family, always AF_INET6. Member of struct sockaddr_in6
     */
    int             sin6_family;    /**< Protocol family, always AF_INET6 */
    in_port_t       sin6_port;      /**< Port number */
    uint32_t        sin6_flowinfo;  /**< IPv6 traffic class and flow information */
    struct in6_addr sin6_addr;      /**< IPv6 address */
    uint32_t        sin6_scope_id;  /**< Set of interfaces for a scope */
};

/**
 * @brief   IPv6 multicast request.
 */
struct ipv6_mreq {
    struct in6_addr ipv6mr_multiaddr;   /**< an IPv6 multicast address */
    unsigned        ipv6mr_interface;   /**< interface index, leave 0 for default */
};
