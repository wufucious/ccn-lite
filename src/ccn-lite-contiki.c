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
#include <stdbool.h>//riot
#include <stdio.h>//riot
#include <stdlib.h>//riot
#include <string.h>//riot
#include <time.h>//riot
#include <unistd.h>//riot


#include <sys/time.h>//where contains timeval and gettimeofday

#include <stdint.h> //add by me //uint32_t uint8_t......


#include "ccn-lite-contiki.h"

#include "ccnl-os-time.c"
#include "ccnl-headers.h"

// ----------------------------------------------------------------------

#undef USE_NFN

// #define USE_DUP_CHECK
// #define USE_IPV4
// #define USE_IPV6
#define USE_SUITE_NDNTLV //move to ccnl-defs.h
#define NEEDS_PREFIX_MATCHING
#define NEEDS_PACKET_CRAFTING

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

int debug_level =VERBOSE;//VERBOSE;												//riot redefined in ccnl-common.c
struct ccnl_relay_s theRelay;									//riot in ccnl-core.h
struct ccnl_face_s *loopback_face;      //riot add

#include "ccnl-core.c"

/*-------------------------------------------------------*/
//uint16_t ntohs(uint16_t val)
//{
//  return HTONS(val);
//}
//
//uint32_t ntohl(uint32_t val)
//{
//  return HTONL(val);
//}

/*-------------------------------------------------------*/
typedef int (*ccnl_mkInterestFunc)(struct ccnl_prefix_s*, int*, unsigned char*, int);
typedef int (*ccnl_isContentFunc)(unsigned char*, int);

#ifdef USE_SUITE_NDNTLV
#ifdef NEEDS_PACKET_CRAFTING
int ndntlv_mkInterest(struct ccnl_prefix_s *name, int *nonce,
                  unsigned char *out, int outlen)
{
    int len, offset;

    offset = outlen;
    len = ccnl_ndntlv_prependInterest(name, -1, nonce, &offset, out);
    if (len > 0)
        memmove(out, out + offset, len);

    return len;
}
#endif // NEEDS_PACKET_CRAFTING

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


// ----------------------------------------------------------------------

#ifdef USE_SUITE_CCNTLV

#ifdef NEEDS_PACKET_CRAFTING
int
ccntlv_mkInterest(struct ccnl_prefix_s *name, int *dummy,
                  unsigned char *out, int outlen)
{
    (void) dummy;
     int len, offset;

     offset = outlen;
     len = ccnl_ccntlv_prependChunkInterestWithHdr(name, &offset, out);
     if (len > 0)
         memmove(out, out + offset, len);

     return len;
}
#endif

struct ccnx_tlvhdr_ccnx2015_s*
ccntlv_isHeader(unsigned char *buf, int len)
{
    struct ccnx_tlvhdr_ccnx2015_s *hp = (struct ccnx_tlvhdr_ccnx2015_s*)buf;

    if ((unsigned int)len < sizeof(struct ccnx_tlvhdr_ccnx2015_s)) {
        DEBUGMSG(ERROR, "ccntlv header not large enough\n");
        return NULL;
    }
    if (hp->version != CCNX_TLV_V1) {
        DEBUGMSG(ERROR, "ccntlv version %d not supported\n", hp->version);
        return NULL;
    }
    if (ntohs(hp->pktlen) < len) {
        DEBUGMSG(ERROR, "ccntlv packet too small (%d instead of %d bytes)\n",
                 ntohs(hp->pktlen), len);
        return NULL;
    }
    return hp;
}

int ccntlv_isData(unsigned char *buf, int len)
{
    struct ccnx_tlvhdr_ccnx2015_s *hp = ccntlv_isHeader(buf, len);

    return hp && hp->pkttype == CCNX_PT_Data;
}

int ccntlv_isFragment(unsigned char *buf, int len)
{
    struct ccnx_tlvhdr_ccnx2015_s *hp = ccntlv_isHeader(buf, len);

    return hp && hp->pkttype == CCNX_PT_Fragment;
}

#endif // USE_SUITE_CCNTLV

// ----------------------------------------------------------------------
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
/*-------------------------------------------------------*/

int ccnl_make_interest(int suite, char *name, /*uint8_t *addr,
                               size_t addr_len,*/ unsigned int *chunknum,
                               unsigned char *buf, size_t buf_len, int *lens)

{
    struct ccnl_prefix_s *prefix;

    if (suite != CCNL_SUITE_NDNTLV && suite != CCNL_SUITE_CCNTLV) {
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

    int nonce = rand();
    /* TODO: support other transports than AF_PACKET */
//     sockunion sun;
//     sun.sa.sa_family = AF_PACKET;//TODO:which AF should I choose?
//     memcpy(&(sun.linklayer.sll_addr), addr, addr_len);
//     sun.linklayer.sll_halen = addr_len;
//
//     struct ccnl_face_s *fibface = ccnl_get_face_or_create(&theRelay, 0, &sun.sa, sizeof(sun.linklayer));
//     fibface->flags |= CCNL_FACE_FLAGS_STATIC;
//     ccnl_add_fib_entry(&theRelay, prefix, fibface);

    DEBUGMSG(DEBUG, "nonce: %i\n", nonce);

    int len = mkInterest(prefix, &nonce, buf, buf_len);
    DEBUGMSG(DEBUG, "interest has %d bytes\n", len);
    *lens = len;

//     unsigned char *start = buf;
//     unsigned char *data = buf;
//     struct ccnl_pkt_s *pkt;
//
//     int typ;
//     int int_len;

     /* TODO: support other suites */
//     if (ccnl_ndntlv_dehead(&data, &len, (int*) &typ, &int_len) || (int) int_len > len) {
//         DEBUGMSG(WARNING, "  invalid packet format\n");
//         return -1;
//     }
//     pkt = ccnl_ndntlv_bytes2pkt(NDN_TLV_Interest, start, &data, &len);
//
//     struct ccnl_interest_s *i = ccnl_interest_new(&theRelay, loopback_face, &pkt);
//     ccnl_interest_append_pending(i, loopback_face);
//     ccnl_interest_propagate(&theRelay, i);
//    return len;
    free_prefix(prefix);
	return 0;
}

int ccnl_make_content(int suite, char *name, char *content,/*uint8_t *addr,
                               size_t addr_len,*/ unsigned int *chunknum,
                               unsigned char *buf, int *lens)

{
    int len = strlen(content);
    int offs = CCNL_MAX_PACKET_SIZE;
//    unsigned char _out[CCNL_MAX_PACKET_SIZE];

    struct ccnl_prefix_s *prefix;

    if (suite != CCNL_SUITE_NDNTLV && suite != CCNL_SUITE_CCNTLV) {
        DEBUGMSG(WARNING, "Suite not supported by Contiki!");
        return -1;
    }

//    ccnl_mkInterestFunc mkInterest;
//    ccnl_isContentFunc isContent;
//
//    mkInterest = ccnl_suite2mkInterestFunc(suite);
//    isContent = ccnl_suite2isContentFunc(suite);

//    if (!mkInterest || !isContent) {
//        DEBUGMSG(WARNING, "No functions for this suite were found!");
//        return(-1);
//    }

    prefix = ccnl_URItoPrefix(name, suite, NULL, chunknum);

    if (!prefix) {
        DEBUGMSG(ERROR, "prefix could not be created!\n");
        return -1;
    }

//    int nonce = rand();
    /* TODO: support other transports than AF_PACKET */
//     sockunion sun;
//     sun.sa.sa_family = AF_PACKET;//TODO:which AF should I choose?
//     memcpy(&(sun.linklayer.sll_addr), addr, addr_len);
//     sun.linklayer.sll_halen = addr_len;
//
//     struct ccnl_face_s *fibface = ccnl_get_face_or_create(&theRelay, 0, &sun.sa, sizeof(sun.linklayer));
//     fibface->flags |= CCNL_FACE_FLAGS_STATIC;
//     ccnl_add_fib_entry(&theRelay, prefix, fibface);

//    DEBUGMSG(DEBUG, "nonce: %i\n", nonce);

//    int len = mkInterest(prefix, &nonce, buf, buf_len);
//    DEBUGMSG(DEBUG, "interest has %d bytes\n", len);
    if(suite == CCNL_SUITE_NDNTLV) len = ccnl_ndntlv_prependContent(prefix,
    		(unsigned char*)content, len, NULL, NULL, &offs, buf);
	if(suite == CCNL_SUITE_CCNTLV) len = ccnl_ccntlv_prependContentWithHdr(prefix,
    		(unsigned char*)content, len, NULL, NULL, &offs, buf);

    DEBUGMSG(DEBUG, "content has %d bytes\n", len);
    if(len==-1) return -1;
    *lens = len;

    unsigned char *olddata;
    unsigned char *data = olddata = buf + offs;

    int int_len;
    unsigned typ;

     /* TODO: support other suites */
//    if (ccnl_ndntlv_dehead(&data, &len, (int*) &typ, &int_len) || (int) int_len > len) {
//         DEBUGMSG(WARNING, "  invalid packet format\n");
//         return -1;
//     }
//    pkt = ccnl_ndntlv_bytes2pkt(NDN_TLV_Interest, start, &data, &len);
//
//    struct ccnl_interest_s *i = ccnl_interest_new(&theRelay, loopback_face, &pkt);
//    ccnl_interest_append_pending(i, loopback_face);
//    ccnl_interest_propagate(&theRelay, i);
    struct ccnl_content_s *c = 0;
    struct ccnl_pkt_s *pk;

    if(suite == CCNL_SUITE_NDNTLV){
        if (ccnl_ndntlv_dehead(&data, &len, (int*) &typ, &int_len) ||
            typ != NDN_TLV_Data) {
            return -1;
        }

        pk= ccnl_ndntlv_bytes2pkt(typ, olddata, &data, &len);
        /*by me copy bytes and chunknum from the former prefix*/
        pk->pfx->bytes=prefix->bytes;
        pk->pfx->chunknum=prefix->chunknum;

        c = ccnl_content_new(&theRelay, &pk);
        c->flags |= CCNL_CONTENT_FLAGS_STALE;//content can be removed
        ccnl_content_add2cache(&theRelay, c);
    //    c->flags |= CCNL_CONTENT_FLAGS_STATIC;
        /*by me prefix and its comp and complen since they are no more needed for the contents*/
        ccnl_free(prefix->complen);
        ccnl_free(prefix->comp);
        ccnl_free(prefix);
    }

    if(suite == CCNL_SUITE_CCNTLV){
    	int hdrlen = ccnl_ccntlv_getHdrLen(data, len);

        if (hdrlen > 0) {
            data += hdrlen;
            len -= hdrlen;
            pk= ccnl_ccntlv_bytes2pkt(olddata, &data, &len);
        }

        /*by me copy bytes and chunknum from the former prefix*/
        pk->pfx->bytes=prefix->bytes;
        pk->pfx->chunknum=prefix->chunknum;

        c = ccnl_content_new(&theRelay, &pk);
        c->flags |= CCNL_CONTENT_FLAGS_STALE;//content can be removed
        ccnl_content_add2cache(&theRelay, c);
    //    c->flags |= CCNL_CONTENT_FLAGS_STATIC;
        /*by me prefix and its comp and complen since they are no more needed for the contents*/
        ccnl_free(prefix->complen);
        ccnl_free(prefix->comp);
        ccnl_free(prefix);
    }
//    return len;
	return offs;
}

int ccnl_find_content(int suite, char *interest, int len, char *buf_out, int *out_len)
{
//    struct ccnl_prefix_s *prefix;

    if (suite != CCNL_SUITE_NDNTLV && suite != CCNL_SUITE_CCNTLV) {
        DEBUGMSG(WARNING, "Suite not supported by Contiki!\n");
        return -1;
    }

    ccnl_mkInterestFunc mkInterest;
    ccnl_isContentFunc isContent;

    mkInterest = ccnl_suite2mkInterestFunc(suite);
    isContent = ccnl_suite2isContentFunc(suite);

    if (!mkInterest || !isContent) {
        DEBUGMSG(WARNING, "No functions for this suite were found!\n");
        return(-1);
    }

//    prefix = ccnl_URItoPrefix(name, suite, NULL, chunknum);
//
//    if (!prefix) {
//        DEBUGMSG(ERROR, "prefix could not be created!\n");
//        return -1;
//    }
//
//    int nonce = rand();
    /* TODO: support other transports than AF_PACKET */
//     sockunion sun;
//     sun.sa.sa_family = AF_PACKET;//TODO:which AF should I choose?
//     memcpy(&(sun.linklayer.sll_addr), addr, addr_len);
//     sun.linklayer.sll_halen = addr_len;
//
//     struct ccnl_face_s *fibface = ccnl_get_face_or_create(&theRelay, 0, &sun.sa, sizeof(sun.linklayer));
//     fibface->flags |= CCNL_FACE_FLAGS_STATIC;
//     ccnl_add_fib_entry(&theRelay, prefix, fibface);

//    DEBUGMSG(DEBUG, "nonce: %i\n", nonce);

//    int len = mkInterest(prefix, &nonce, buf, buf_len);
    DEBUGMSG(DEBUG, "interest has %d bytes\n", len);
//    *lens = len;

    unsigned char *start = interest;
    unsigned char *data = interest;
    struct ccnl_pkt_s *pkt;

    int typ;
    int int_len;

    struct ccnl_content_s *c2;

	if (suite == CCNL_SUITE_NDNTLV) {
		if (ccnl_ndntlv_dehead(&data, &len, (int*) &typ, &int_len) || (int) int_len > len) {
			 DEBUGMSG(WARNING, "  invalid packet format\n");
			 return -1;
		 }
		pkt = ccnl_ndntlv_bytes2pkt(NDN_TLV_Interest, start, &data, &len);
		pkt->s.ndntlv.minsuffix = 0;
		pkt->s.ndntlv.ppkl= NULL;
		// 	if(ccnl_ndntlv_cMatch(pkt, theRelay.contents)==-1)
		//    	 DEBUGMSG(DEBUG, "can not find match content\n");

		for (c2 = theRelay.contents; c2; c2 = c2->next){
			if(ccnl_ndntlv_cMatch(pkt, c2)==0){
				int i = c2->pkt->buf->datalen;
				DEBUGMSG(TRACE, "after compared all contents, "
						"got match content finally and write it to output buffer\n");
				memcpy(buf_out, c2->pkt->buf->data, i);
				*out_len=i;
				DEBUGMSG(TRACE, "output buffer size is %d\n", i);
				break;
			}
		}
	}

	if (suite == CCNL_SUITE_CCNTLV) {
    	int hdrlen = ccnl_ccntlv_getHdrLen(data, len);

        if (hdrlen > 0) {
            data += hdrlen;
            len -= hdrlen;
            pkt= ccnl_ccntlv_bytes2pkt(start, &data, &len);
        }
//		pkt->s.ndntlv.minsuffix = 0;

		// 	if(ccnl_ndntlv_cMatch(pkt, theRelay.contents)==-1)
		//    	 DEBUGMSG(DEBUG, "can not find match content\n");

		for (c2 = theRelay.contents; c2; c2 = c2->next){
			if(ccnl_ccntlv_cMatch(pkt, c2)==0){
				int i = c2->pkt->buf->datalen;
				DEBUGMSG(TRACE, "after compared all contents, "
						"got match content finally and write it to output buffer\n");
				memcpy(buf_out, c2->pkt->buf->data, i);
				*out_len=i;
				DEBUGMSG(TRACE, "output buffer size is %d\n", i);
				break;
			}
		}
	}

    free_packet(pkt);

    if(c2 == NULL) {
  		DEBUGMSG(TRACE, "after compared all contents,"
  		 			"can not find any match data in buffer\n");
  		return -1;
  	}
	return 0;
}
