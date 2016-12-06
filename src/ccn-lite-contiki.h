#ifndef CCN_LITE_CONTIKI_H
#define CCN_LITE_CONTIKI_H

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>

#define CCNL_CONTIKI

#define USE_SUITE_NDNTLV
#define USE_SUITE_CCNTLV

#define SOCKADDR_MAX_DATA_LEN   (26)
typedef unsigned short sa_family_t;   /**< address family type */ //copy from RIOT socket.h
struct sockaddr {
	sa_family_t sa_family;                  /**< Address family */
	char sa_data[SOCKADDR_MAX_DATA_LEN];    /**< Socket address (variable length data) */
};

#include "ccnl-defs.h"
#include "ccnl-core.h"
#include "ccnl-headers.h"

#define FATAL   0 // FATAL
#define ERROR   1 // ERROR
#define WARNING 2 // WARNING
#define INFO    3 // INFO
#define DEBUG   4 // DEBUG
#define TRACE   5 // TRACE
#define VERBOSE 6 // VERBOSE

#define DEBUGMSG(LVL, ...) do {       \
        if ((LVL)>debug_level) break;   \
        printf(__VA_ARGS__);   \
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

/*-----------------------------------------------*/
//#define ccnl_malloc(s)                  malloc(s)
//#define ccnl_calloc(n,s)                malloc(n*s)
//#define ccnl_realloc(p,s)               realloc(p,s)
//#define ccnl_free(p)                    free(p)
/*-----------------------------------------------*/
#include <heapmem.h>
#define ccnl_malloc(s)                  heapmem_alloc(s)
#define ccnl_calloc(n,s)                heapmem_alloc(n*s)
#define ccnl_free(p)                    heapmem_free(p)
/*-----------------------------------------------*/

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
#define cache_strategy_remove(...)      0

/*-----------------------------------------------*/
#include "net/ip/uip.h"

#define ntohs uip_ntohs
#define ntohl uip_ntohl

#define htons ntohs
#define htonl ntohl
/*---------------------------------------------------------------------------*/
#define AF_PACKET 1
#define AF_INET   2
#define AF_INET6  3
#define AF_UNIX   4
/*---------------------------------------------------------------------------*/
int ccnl_init();
int ccnl_make_interest(int suite, char *name, unsigned int *chunknum,
                      unsigned char *buf, size_t buf_len, int* len);

void my_ccnl_do_ageing();

int ccnl_cache_search(struct ccnl_pkt_s *pkt);

int ccnl_make_content(int suite, char *name, char *content, unsigned int *chunknum,
                      unsigned char *buf, int* len);

int ccnl_find_content(int suite, char *interest, int len, char *buf, int *lens);

int ccnl_cache_content(int suite, char *name, char *content, int len, unsigned char *buf, int *lens);
/*---------------------------------------------------------------------------*/
#endif /* CCN_LITE_CONTIKI_H */
