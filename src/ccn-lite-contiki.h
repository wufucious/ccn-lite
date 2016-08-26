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

//#include "stdlibc/malloc.h"
#define ccnl_malloc(s)                  malloc(s)
#define ccnl_calloc(n,s)                malloc(n*s)
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
#define cache_strategy_remove(...)      0

/*-----------------------------------------------*/
//copy from uip.h in Contiki. implemnt the ntohs and ntohl functions
//#define HTONS(n) (uint16_t)((((uint16_t) (n)) << 8) | (((uint16_t) (n)) >> 8))
//#define HTONL(n) (((uint32_t)HTONS(n) << 16) | HTONS((uint32_t)(n) >> 16))
//
//uint16_t ntohs(uint16_t val);
//uint32_t ntohl(uint32_t val);
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
int ccnl_make_interest(int suite, char *name, unsigned int *chunknum,
                      unsigned char *buf, size_t buf_len, int* len);

int ccnl_make_content(int suite, char *name, char *content, unsigned int *chunknum,
                      unsigned char *buf, int* len);

int ccnl_find_content(int suite, char *interest, int len,char *buf, int *lens);


// void *ccnl_malloc(size_t size); // Allocate uninitialized memory.
// void *ccnl_calloc(size_t number, size_t size); // Allocate zero-initialized memory.
// void *ccnl_realloc(void *ptr, size_t size); // Change the size of an allocated object.
// void ccnl_free(void *ptr); // Free memory.
/*---------------------------------------------------------------------------*/
#endif /* CCN_LITE_CONTIKI_H */
