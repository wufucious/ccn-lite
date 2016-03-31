/*
 * @f ccn-lite-minimalrelay.c
 * @b user space NDN relay, minimalist version
 *
 * Copyright (C) 2011-14, Christian Tschudin, University of Basel
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * File history:
 * 2012-08-02 created
 * 2014-11-05 small code cleanups, now using NDNTLV as default encoding
 */
#define CCNL_CONTIKI

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

// #include <sys/ioctl.h>
// #include <sys/select.h>
// #include <sys/socket.h>// riot "sys/socket.h"
#include <sys/time.h>//where contains timeval and gettimeofday
// #include <sys/types.h>
// #include <sys/un.h>
#include <stdint.h> //add by me //uint32_t uint8_t......

// #include <arpa/inet.h>//riot
// #include <netinet/in.h>

#include "ccn-lite-contiki.h"

#include "ccnl-os-time.c"
#include "ccnl-headers.h"
// #ifndef _DEFAULT_SOURCE
// int inet_aton(const char *cp, struct in_addr *inp);
// #endif

// ----------------------------------------------------------------------

#undef USE_NFN

// #define USE_DUP_CHECK
// #define USE_IPV4
// #define USE_IPV6
// #define USE_SUITE_NDNTLV //move to ccnl-defs.h
#define NEEDS_PREFIX_MATCHING

#include "ccnl-defs.h"
#include "ccnl-core.h"

void free_packet(struct ccnl_pkt_s *pkt);

struct ccnl_interest_s* ccnl_interest_remove(struct ccnl_relay_s *ccnl,
                     struct ccnl_interest_s *i);
int ccnl_pkt2suite(unsigned char *data, int len, int *skip);

char* ccnl_prefix_to_path_detailed(struct ccnl_prefix_s *pr,
                    int ccntlv_skip, int escape_components, int call_slash);
#define ccnl_prefix_to_path(P) ccnl_prefix_to_path_detailed(P, 1, 0, 0)

char* ccnl_addr2ascii(sockunion *su);
void ccnl_core_addToCleanup(struct ccnl_buf_s *buf);
const char* ccnl_suite2str(int suite);
bool ccnl_isSuite(int suite);
//riot
//----------------------------------------------------------------------
static inline void ccnl_ll_TX(struct ccnl_relay_s *r, struct ccnl_if_s *i,				//riot diff
                sockunion *a, struct ccnl_buf_s *b)
{
    // sendto(i->sock,b->data,b->datalen,r?0:0,(struct sockaddr*)&(a)->ip4,sizeof(struct sockaddr_in));
}

struct ccnl_buf_s*																		//riot
ccnl_buf_new(void *data, int len)
{
    struct ccnl_buf_s *b = ccnl_malloc(sizeof(*b) + len);

    if (!b)
        return NULL;
    b->next = NULL;
    b->datalen = len;
    if (data)
        memcpy(b->data, data, len);
    return b;
}

// ----------------------------------------------------------------------
// timer support and event server
// copied from ccnl-os-time.c
// (because we do not want to have includes beyond the core CCN logic)

// void
// ccnl_get_timeval(struct timeval *tv)						//riot moved to ccnl-os-time.c,
// {
//     gettimeofday(tv, NULL);
// }

// long
// timevaldelta(struct timeval *a, struct timeval *b) {		//riot moved to ccnl-os-time.c, $timeval defined in <bits/time.h>, need redefined
//     return 1000000*(a->tv_sec - b->tv_sec) + a->tv_usec - b->tv_usec;
// }

// struct ccnl_timer_s {										//riot moved to ccnl-os-time.c,
//     struct ccnl_timer_s *next;
//     struct timeval timeout;
//     void (*fct)(char,int);
//     void (*fct2)(void*,void*);
//     char node;
//     int intarg;
//     void *aux1;
//     void *aux2;
//     int handler;
// };

// struct ccnl_timer_s *eventqueue;							//riot moved to ccnl-os-time.c,

// void*
// ccnl_set_timer(int usec, void (*fct)(void *aux1, void *aux2),//riot moved to ccnl-os-time.c,
//                  void *aux1, void *aux2)
// {
//     struct ccnl_timer_s *t, **pp;
//     static int handlercnt;
//
//     t = (struct ccnl_timer_s *) ccnl_calloc(1, sizeof(*t));
//     if (!t)
//         return 0;
//     t->fct2 = fct;
//     gettimeofday(&t->timeout, NULL);
//     usec += t->timeout.tv_usec;
//     t->timeout.tv_sec += usec / 1000000;
//     t->timeout.tv_usec = usec % 1000000;
//     t->aux1 = aux1;
//     t->aux2 = aux2;
//
//     for (pp = &eventqueue; ; pp = &((*pp)->next)) {
//         if (!*pp || (*pp)->timeout.tv_sec > t->timeout.tv_sec ||
//             ((*pp)->timeout.tv_sec == t->timeout.tv_sec &&
//              (*pp)->timeout.tv_usec > t->timeout.tv_usec)) {
//             t->next = *pp;
//             t->handler = handlercnt++;
//             *pp = t;
//             return t;
//         }
//     }
//     return NULL; // ?
// }

// void
// ccnl_rem_timer(void *h)                                    //riot moved to ccnl-os-time.c,
// {
//     struct ccnl_timer_s **pp;
//
//     for (pp = &eventqueue; *pp; pp = &((*pp)->next)) {
//         if ((void*)*pp == h) {
//             struct ccnl_timer_s *e = *pp;
//             *pp = e->next;
//             ccnl_free(e);
//             break;
//         }
//     }
// }

// double
// CCNL_NOW()													//riot moved to ccnl-os-time.c,
// {
//     struct timeval tv;
//     static time_t start;
//     static time_t start_usec;
//
//     ccnl_get_timeval(&tv);
//
//     if (!start) {
//         start = tv.tv_sec;
//         start_usec = tv.tv_usec;
//     }
//
//     return (double)(tv.tv_sec) - start +
//                 ((double)(tv.tv_usec) - start_usec) / 1000000;
// }

// struct timeval*
// ccnl_run_events()												//changed to the "int ccnl_run_events()" in ccnl-os-time.c
// {
//     static struct timeval now;
//     long usec;
//
//     gettimeofday(&now, 0);
//     while (eventqueue) {
//         struct ccnl_timer_s *t = eventqueue;
//         usec = timevaldelta(&(t->timeout), &now);
//         if (usec >= 0) {
//             now.tv_sec = usec / 1000000;
//             now.tv_usec = usec % 1000000;
//             return &now;
//         }
//         else if (t->fct2)
//             (t->fct2)(t->aux1, t->aux2);
//         eventqueue = t->next;
//         ccnl_free(t);
//     }
//     return NULL;
// }

// ----------------------------------------------------------------------

int debug_level;												//riot redefined in ccnl-common.c
struct ccnl_relay_s theRelay;									//riot in ccnl-core.h
struct ccnl_face_s *loopback_face;      //riot add

#include "ccnl-core.c"

// ----------------------------------------------------------------------
// UDP socket, main event loop

// int
// ccnl_open_udpdev(int port)
// {
//     int s;
//     struct sockaddr_in si;
//
//     s = socket(PF_INET, SOCK_DGRAM, 0);
//     if (s < 0) {
//         perror("udp socket");
//         return -1;
//     }
//
//     si.sin_addr.s_addr = INADDR_ANY;
//     si.sin_port = htons(port);
//     si.sin_family = PF_INET;
//     if (bind(s, (struct sockaddr *)&si, sizeof(si)) < 0) {
//         perror("udp sock bind");
//         return -1;
//     }
//
//     return s;
// }
//
// void ccnl_minimalrelay_ageing(void *relay, void *aux)
// {
//     ccnl_do_ageing(relay, aux);
//     ccnl_set_timer(1000000, ccnl_minimalrelay_ageing, relay, 0);
// }
//
// void
// ccnl_io_loop(struct ccnl_relay_s *ccnl)
// {
//     int i, maxfd = -1, rc;
//     fd_set readfs, writefs;
//
//     if (ccnl->ifcount == 0) {
//         fprintf(stderr, "no socket to work with, not good, quitting\n");
//         exit(EXIT_FAILURE);
//     }
//     for (i = 0; i < ccnl->ifcount; i++)
//         if (ccnl->ifs[i].sock > maxfd)
//             maxfd = ccnl->ifs[i].sock;
//     maxfd++;
//
//     FD_ZERO(&readfs);
//     FD_ZERO(&writefs);
//     while(!ccnl->halt_flag) {
//         struct timeval *timeout;
//
//         for (i = 0; i < ccnl->ifcount; i++) {
//             FD_SET(ccnl->ifs[i].sock, &readfs);
//             if (ccnl->ifs[i].qlen > 0)
//                 FD_SET(ccnl->ifs[i].sock, &writefs);
//             else
//                 FD_CLR(ccnl->ifs[i].sock, &writefs);
//         }
//
//         timeout = ccnl_run_events();
//         rc = select(maxfd, &readfs, &writefs, NULL, timeout);
//         if (rc < 0) {
//             perror("select(): ");
//             exit(EXIT_FAILURE);
//         }
//
//         for (i = 0; i < ccnl->ifcount; i++) {
//             if (FD_ISSET(ccnl->ifs[i].sock, &readfs)) {
//                 sockunion src_addr;
//                 socklen_t addrlen = sizeof(sockunion);
//                 unsigned char buf[CCNL_MAX_PACKET_SIZE];
//                 int len;
//                 if ((len = recvfrom(ccnl->ifs[i].sock, buf, sizeof(buf), 0,
//                                 (struct sockaddr*) &src_addr, &addrlen)) > 0)
//                     ccnl_core_RX(ccnl, i, buf, len, &src_addr.sa, sizeof(src_addr.ip4));
//             }
//             if (FD_ISSET(ccnl->ifs[i].sock, &writefs))
//                 ccnl_interface_CTS(&theRelay, &theRelay.ifs[0]);
//         }
//     }
// }

// ----------------------------------------------------------------------

// int
// main(int argc, char **argv)
// {
//     int opt;
//     int udpport = 0;
//     char *prefix, *defaultgw;
//     struct ccnl_if_s *i;
//     struct ccnl_forward_s *fwd;
//     sockunion sun;
//
//     srandom(time(NULL));
//
//     int suite = CCNL_SUITE_NDNTLV;
//
//     while ((opt = getopt(argc, argv, "hs:u:v:")) != -1) {
//         switch (opt) {
//         case 's':
//             opt = ccnl_str2suite(optarg);
//             if (opt >= 0 && opt < CCNL_SUITE_LAST)
//                 suite = opt;
//             else
//                 fprintf(stderr, "Suite parameter <%s> ignored.\n", optarg);
//             break;
//         case 'u':
//             udpport = atoi(optarg);
//             break;
//         case 'v':
//             debug_level = atoi(optarg);
//             break;
//         case 'h':
//         default:
// usage:
//             fprintf(stderr,
//                     "usage:    %s [options] PREFIX DGWIP/DGWUDPPORT\n"
//                     "options:  [-h] [-s SUITE] [-u udpport] [-v debuglevel]\n"
//                     "example:  %s /ndn 128.252.153.194/6363\n",
//                     argv[0], argv[0]);
//             exit(EXIT_FAILURE);
//         }
//     }
//
//     if ((optind+1) >= argc)
//         goto usage;
//     prefix = argv[optind];
//     defaultgw = argv[optind+1];
//
//     ccnl_core_init();
//
// //    if (theRelay.suite == CCNL_SUITE_NDNTLV && !udpport)
//         udpport = NDN_UDP_PORT;
//
//     i = &theRelay.ifs[0];
//     i->mtu = NDN_DEFAULT_MTU;
//     i->fwdalli = 1;
//     i->sock = ccnl_open_udpdev(udpport);
//     if (i->sock < 0)
//         exit(-1);
//     theRelay.ifcount++;
//     fprintf(stderr, "NDN minimalrelay started, listening on UDP port %d\n",
//             udpport);
//
//     inet_aton(strtok(defaultgw,"/"), &sun.ip4.sin_addr);
//     sun.ip4.sin_port = atoi(strtok(NULL, ""));
//     fwd = (struct ccnl_forward_s *) ccnl_calloc(1, sizeof(*fwd));
//     fwd->prefix = ccnl_URItoPrefix(prefix, suite, NULL, NULL);
//     fwd->suite = suite;
//     fwd->face = ccnl_get_face_or_create(&theRelay, 0, &sun.sa, sizeof(sun.ip4));
//     fwd->face->flags |= CCNL_FACE_FLAGS_STATIC;
//     theRelay.fib = fwd;
//
//     ccnl_set_timer(1000000, ccnl_minimalrelay_ageing, &theRelay, 0);
//     ccnl_io_loop(&theRelay);
//
//     return 0;
// }
int suite = CCNL_SUITE_NDNTLV;
/*---------------------------------------------------------------------------*/
uint16_t
ntohs(uint16_t val)
{
  return HTONS(val);
}

uint32_t
ntohl(uint32_t val)
{
  return HTONL(val);
}
/*---------------------------------------------------------------------------*/
// int main(int argc, char const *argv[]) {
//   // suite = CCNL_SUITE_NDNTLV;
//   /* code */
//   ccnl_core_init();
//   printf("%s\n","hello world" );
//   return 0;
// }
// eof
typedef int (*ccnl_mkInterestFunc)(struct ccnl_prefix_s*, int*, unsigned char*, int);
typedef int (*ccnl_isContentFunc)(unsigned char*, int);
// extern ccnl_mkInterestFunc ccnl_suite2mkInterestFunc(int suite);
// extern ccnl_isContentFunc ccnl_suite2isContentFunc(int suite);

/*------copy from ccnl-common.c------*/
#ifdef USE_SUITE_NDNTLV

//#ifdef NEEDS_PACKET_CRAFTING
int
ndntlv_mkInterest(struct ccnl_prefix_s *name, int *nonce,
                  unsigned char *out, int outlen)
{
    int len, offset;

    offset = outlen;
    len = ccnl_ndntlv_prependInterest(name, -1, nonce, &offset, out);
    if (len > 0)
        memmove(out, out + offset, len);

    return len;
}
//#endif // NEEDS_PACKET_CRAFTING

int ndntlv_isData(unsigned char *buf, int len)
{
    int typ;
    int vallen;

    if (len < 0 || ccnl_ndntlv_dehead(&buf, &len, (int*) &typ, &vallen))
        return -1;
    if (typ != NDN_TLV_Data)
        return 0;
    return 1;
}
#endif // USE_SUITE_NDNTLV

ccnl_mkInterestFunc
ccnl_suite2mkInterestFunc(int suite)
{
    switch(suite) {
#ifdef USE_SUITE_CCNB
    case CCNL_SUITE_CCNB:
        return &ccnl_ccnb_fillInterest;
#endif
#ifdef USE_SUITE_CCNTLV
    case CCNL_SUITE_CCNTLV:
        return &ccntlv_mkInterest;
#endif
#ifdef USE_SUITE_CISTLV
    case CCNL_SUITE_CISTLV:
        return &cistlv_mkInterest;
#endif
#ifdef USE_SUITE_IOTTLV
    case CCNL_SUITE_IOTTLV:
        return &iottlv_mkRequest;
#endif
#ifdef USE_SUITE_NDNTLV
    case CCNL_SUITE_NDNTLV:
        return &ndntlv_mkInterest;
#endif
    }

    DEBUGMSG(WARNING, "unknown suite %d in %s:%d\n",
                      suite, __func__, __LINE__);
    return NULL;
}

ccnl_isContentFunc
ccnl_suite2isContentFunc(int suite)
{
    switch(suite) {
#ifdef USE_SUITE_CCNB
    case CCNL_SUITE_CCNB:
        return &ccnb_isContent;
#endif
#ifdef USE_SUITE_CCNTLV
    case CCNL_SUITE_CCNTLV:
        return &ccntlv_isData;
#endif
#ifdef USE_SUITE_CISTLV
    case CCNL_SUITE_CISTLV:
        return &cistlv_isData;
#endif
#ifdef USE_SUITE_IOTTLV
    case CCNL_SUITE_IOTTLV:
        return &iottlv_isReply;
#endif
#ifdef USE_SUITE_NDNTLV
    case CCNL_SUITE_NDNTLV:
        return &ndntlv_isData;
#endif
    }

    DEBUGMSG(WARNING, "unknown suite %d in %s:%d\n",
                      suite, __func__, __LINE__);
    return NULL;
}

int
ccnl_send_interest(/*int suite,*/ char *name, /*uint8_t *addr,
                               size_t addr_len,*/ unsigned int *chunknum,
                               unsigned char *buf, size_t buf_len)

{
    struct ccnl_prefix_s *prefix;

    if (suite != CCNL_SUITE_NDNTLV) {
        DEBUGMSG(WARNING, "Suite not supported by Contiki!");
        return -1;
    }

    ccnl_mkInterestFunc mkInterest;
    ccnl_isContentFunc isContent;

    mkInterest = ccnl_suite2mkInterestFunc(suite);
    isContent = ccnl_suite2isContentFunc(suite);

    if (!mkInterest || !isContent) {
        DEBUGMSG(WARNING, "No functions for this suite were found!");
        return(-1);
    }

    prefix = ccnl_URItoPrefix(name, suite, NULL, chunknum);

    if (!prefix) {
        DEBUGMSG(ERROR, "prefix could not be created!\n");
        return -1;
    }

    // int nonce = random();
    srand ( time(NULL) );
    int nonce = rand();
    /* TODO: support other transports than AF_PACKET */
    // sockunion sun;
    // sun.sa.sa_family = AF_PACKET;//TODO:which AF should I choose?
    // memcpy(&(sun.linklayer.sll_addr), addr, addr_len);
    // sun.linklayer.sll_halen = addr_len;

    // struct ccnl_face_s *fibface = ccnl_get_face_or_create(&theRelay, 0, &sun.sa, sizeof(sun.linklayer));
    // fibface->flags |= CCNL_FACE_FLAGS_STATIC;
    // ccnl_add_fib_entry(&theRelay, prefix, fibface);

    DEBUGMSG(DEBUG, "nonce: %i\n", nonce);

    int len = mkInterest(prefix, &nonce, buf, buf_len);

    unsigned char *start = buf;
    unsigned char *data = buf;
    struct ccnl_pkt_s *pkt;

    int typ;
    int int_len;

    /* TODO: support other suites */
    if (ccnl_ndntlv_dehead(&data, &len, (int*) &typ, &int_len) || (int) int_len > len) {
        DEBUGMSG(WARNING, "  invalid packet format\n");
        return -1;
    }
    pkt = ccnl_ndntlv_bytes2pkt(NDN_TLV_Interest, start, &data, &len);

    struct ccnl_interest_s *i = ccnl_interest_new(&theRelay, loopback_face, &pkt);
    ccnl_interest_append_pending(i, loopback_face);
    ccnl_interest_propagate(&theRelay, i);

    return 0;
}
