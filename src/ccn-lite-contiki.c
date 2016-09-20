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
//#include <sys/time.h>//where contains timeval and gettimeofday
#include <stdint.h> //add by me //uint32_t uint8_t......
#include <limits.h> //INT_MAX...

#include "ccn-lite-contiki.h"

// #define USE_DUP_CHECK
#define USE_SUITE_NDNTLV //move to ccnl-defs.h
#define NEEDS_PREFIX_MATCHING
#define NEEDS_PACKET_CRAFTING

#define INTEREST_PENDING
//#define CONTENT_CACHE
/*-------------------------------------------------------------------*/
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
/*-------------------------------------------------------------------*/
struct ccnl_buf_s*
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

/*-------------------------------------------------------------------*/
//#include "ccnl-os-time.c"//Contiki time different from others, implement here
#define CCNL_NOW()                    current_time()

/*in ccn-lite code, last_used is int but used as unsignedess int,
use % to avoid overflow and limit i between 0 to INT_MAX
it also works when sizeof(unsigned long)>sizeof(int) */
int
current_time(void)
{
	unsigned long i = clock_time();//get the current time from Contiki
	int j;

	if (i > INT_MAX) j = i % ((unsigned long)INT_MAX+1);
	else j = i;

	return j;
}

//char*
//timestamp(void)
//{
//    static char ts[16], *cp;
//
//    sprintf(ts, "%.4g", CCNL_NOW());
//    cp = strchr(ts, '.');
//    if (!cp)
//        strcat(ts, ".0000");
//    else if (strlen(cp) > 5)
//        cp[5] = '\0';
//    else while (strlen(cp) < 5)
//        strcat(cp, "0");
//
//    return ts;
//}

//struct ccnl_timer_s {
//    struct ccnl_timer_s *next;
//    struct timeval timeout;
//    void (*fct)(char,int);
//    void (*fct2)(void*,void*);
//    char node;
//    int intarg;
//    void *aux1;
//    void *aux2;
//  //    int handler;
//};
//
//struct ccnl_timer_s *eventqueue;

//void
//ccnl_get_timeval(struct timeval *tv)
//{
//    gettimeofday(tv, NULL);
//}

//long
//timevaldelta(struct timeval *a, struct timeval *b) {
//    return 1000000*(a->tv_sec - b->tv_sec) + a->tv_usec - b->tv_usec;
//}
//
//void*
//ccnl_set_timer(uint64_t usec, void (*fct)(void *aux1, void *aux2),
//                 void *aux1, void *aux2)
//{
//    struct ccnl_timer_s *t, **pp;
//    //    static int handlercnt;
//
//    t = (struct ccnl_timer_s *) ccnl_calloc(1, sizeof(*t));
//    if (!t)
//        return 0;
//    t->fct2 = fct;
//    gettimeofday(&t->timeout, NULL);
//    usec += t->timeout.tv_usec;
//    t->timeout.tv_sec += usec / 1000000;
//    t->timeout.tv_usec = usec % 1000000;
//    t->aux1 = aux1;
//    t->aux2 = aux2;
//
//    for (pp = &eventqueue; ; pp = &((*pp)->next)) {
//    if (!*pp || (*pp)->timeout.tv_sec > t->timeout.tv_sec ||
//        ((*pp)->timeout.tv_sec == t->timeout.tv_sec &&
//         (*pp)->timeout.tv_usec > t->timeout.tv_usec)) {
//        t->next = *pp;
//        //        t->handler = handlercnt++;
//        *pp = t;
//        return t;
//    }
//    }
//    return NULL; // ?
//}
//
//void
//ccnl_rem_timer(void *h)
//{
//    struct ccnl_timer_s **pp;
//
//    for (pp = &eventqueue; *pp; pp = &((*pp)->next)) {
//        if ((void*)*pp == h) {
//            struct ccnl_timer_s *e = *pp;
//            *pp = e->next;
//            ccnl_free(e);
//            break;
//        }
//    }
//}

/*-------------------------------------------------------------------*/
int debug_level =VERBOSE;//VERBOSE;												//riot redefined in ccnl-common.c
struct ccnl_relay_s theRelay;									//riot in ccnl-core.h
struct ccnl_face_s *loopback_face;      //riot add

#include "ccnl-core.c"
/*-------------------------------------------------------------------*/
//dummy
void
ccnl_ll_TX(struct ccnl_relay_s *ccnl, struct ccnl_if_s *ifc,
           sockunion *dest, struct ccnl_buf_s *buf)
{
	return;
}
/*-------------------------------------------------------------------*/
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


/*-------------------------------------------------------------------*/
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

/*-------------------------------------------------------------------*/
typedef int (*ccnl_mkInterestFunc)(struct ccnl_prefix_s*, int*, unsigned char*, int);
typedef int (*ccnl_isContentFunc)(unsigned char*, int);

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
int ccnl_init()
{
	loopback_face = ccnl_get_face_or_create(&theRelay, -1, NULL, 0);
	loopback_face->flags |= CCNL_FACE_FLAGS_STATIC;

	theRelay.max_cache_entries = CCNL_MAX_CACHE_ENTRIES;
	theRelay.max_pit_entries = CCNL_MAX_PIT_ENTRIES;

	return 0;
}

void
my_ccnl_do_ageing()
{
//    struct ccnl_content_s *c = relay->contents;
    struct ccnl_interest_s *i = theRelay.pit;
    int t = CCNL_NOW();
    DEBUGMSG_CORE(VERBOSE, "ageing t=%d\n", (int)(t/CLOCK_SECOND));

//    while (c) {
//        if ((c->last_used + CCNL_CONTENT_TIMEOUT) <= t &&
//                                !(c->flags & CCNL_CONTENT_FLAGS_STATIC)){
//          DEBUGMSG_CORE(TRACE, "AGING: CONTENT REMOVE %p\n", (void*) c);
//            c = ccnl_content_remove(relay, c);
//        }
//        else
//            c = c->next;
//    }

    while (i) { // CONFORM: "Entries in the PIT MUST timeout rather
                // than being held indefinitely."
        if ((i->last_used + MY_CCNL_INTEREST_TIMEOUT) <= t /*&&
                                i->retries >= CCNL_MAX_INTEREST_RETRANSMIT*/) {
            char *s = NULL;
            DEBUGMSG_CORE(TRACE, "AGING: INTEREST REMOVE %p\n", (void*) i);
            DEBUGMSG_CORE(DEBUG, " timeout: remove interest 0x%p <%s>\n",
                          (void*)i,
                     (s = ccnl_prefix_to_path(i->pkt->pfx)));
            ccnl_free(s);
            ccnl_interest_remove(&theRelay, i);
        }
        i = i->next;
    }

    return;
}

int ccnl_cache_search(struct ccnl_pkt_s *pkt)
{
	struct ccnl_interest_s *i;

	for(i = theRelay.pit; i; i = i->next){
	    if (i->pkt->pfx->suite == pkt->suite &&
	    		!ccnl_prefix_cmp(i->pkt->pfx, NULL, pkt->pfx, CMP_EXACT)){
			DEBUGMSG(TRACE, "found pending interest which match this content "
	  				"object, going to remove that interest from pit\n");
	  		ccnl_interest_remove(&theRelay, i);
			return 1;
		}
	}
	DEBUGMSG(TRACE, "after search the pit cache, can not "
			"found pending interest which match this content \n");
	return 0;
}

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
        c->flags = CCNL_CONTENT_FLAGS_STALE;//content can be removed
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
        c->flags = CCNL_CONTENT_FLAGS_STALE;//content can be removed
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

    unsigned char *start = (unsigned char *) interest;
    unsigned char *data = (unsigned char *) interest;
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
				DEBUGMSG(TRACE, "NDNTLV searching, after compared all contents, "
						"got match content finally, going to write it to output buffer\n");
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
				DEBUGMSG(TRACE, "CCNTLV searching, after compared all contents, "
						"got match content finally and write it to output buffer\n");
//				memcpy(buf_out, c2->pkt->buf->data, i);
//				*out_len=i;
//				DEBUGMSG(TRACE, "output buffer size is %d\n", i);
				break;
			}
		}
	}

    if(c2){
		//if buf empty, online generate ccn data and cache it or abort
		struct ccnl_buf_s *b2 = c2->pkt->buf;
		if(!b2){
			b2 = ccnl_mkSimpleContent(c2->pkt->pfx,
					c2->pkt->content, c2->pkt->contlen, 0);
			if(!b2){
				DEBUGMSG(ERROR, "content buffer could not be created!\n");
				return -1;
			}
		}

		int i = b2->datalen;
		memcpy(buf_out, b2->data, i);
		*out_len=i;
		DEBUGMSG(TRACE, "output content size is %d\n", i);
#ifndef CONTENT_CACHE
		ccnl_free(b2);		//abort content
		DEBUGMSG(TRACE, "Abort the new generated data\n");
#else
		c2->pkt->buf = b2;//cache content
		DEBUGMSG(TRACE, "Cache the new generated data\n");
#endif
    }else{
  		DEBUGMSG(TRACE, "after compared all contents,"
  		 			"can not find any match data in buffer\n");
#ifndef INTEREST_PENDING
  		free_packet(pkt);
#else
//  		pkt->pfx->suite = suite;
  		//check if pit already has this interest
  		struct ccnl_interest_s *i;

  		for(i = theRelay.pit; i; i = i->next){
  			if(ccnl_interest_isSame(i,pkt)){
  	  			DEBUGMSG(TRACE, "This interest already in pit\n");
  				break;
  			}
  		}

  		if(i){
  			DEBUGMSG(TRACE, "update last_used value of that interest\n");
  			i->last_used = CCNL_NOW();
  			free_packet(pkt);
  		}else{
  			DEBUGMSG(TRACE, "This interest not yet in pit, going to cache it\n");
  			struct ccnl_interest_s *i2 = ccnl_interest_new(&theRelay, loopback_face, &pkt);
  			if(!i2){
  				DEBUGMSG(TRACE, "cache interest failed!\n");
  				free_packet(pkt);
  			}else{
  				DEBUGMSG(TRACE, "cache interest sucess!\n");
  				//ccnl_free(pkt->buf);//TODO:remove dummy to save space, but this seems cause prefix problem
  			}
  		}

#endif
  		return 1;

  	}

    free_packet(pkt);
	return 0;
}

int ccnl_cache_content(int suite, char *name, char *content, int len, unsigned char *buf_out, int *out_len)
{
    struct ccnl_prefix_s *prefix;

    if (suite != CCNL_SUITE_NDNTLV && suite != CCNL_SUITE_CCNTLV) {
        DEBUGMSG(WARNING, "Suite not supported by Contiki!");
        return -1;
    }

    prefix = ccnl_URItoPrefix(name, suite, NULL, NULL);

    if (!prefix) {
        DEBUGMSG(ERROR, "prefix could not be created!\n");
        return -1;
    }

    struct ccnl_content_s *c =0;
    struct ccnl_pkt_s *pk;

    pk = (struct ccnl_pkt_s*) ccnl_calloc(1, sizeof(*pk));
    if(!pk){
    	DEBUGMSG(ERROR, "pkg could not be created!\n");
    	free_prefix(prefix);
       	return -1;
    }

    pk->suite = suite;
    pk->pfx = prefix;
    pk->content = (unsigned char *)ccnl_malloc(len);
    pk->contlen = len;

    if(!pk->content){
    	DEBUGMSG(ERROR, "content could not be created!\n");
    	free_prefix(prefix);
    	free_packet(pk);
    	return -1;
    }

    memcpy(pk->content, content, len);

    c = ccnl_content_new(&theRelay, &pk);
    c->flags = CCNL_CONTENT_FLAGS_STALE;//content can be removed
    c->pkt->buf = NULL;//data empty buffer, generate ccn data when needed
    ccnl_content_add2cache(&theRelay, c);

    if(ccnl_cache_search(c->pkt)){
		struct ccnl_buf_s *b= ccnl_mkSimpleContent(c->pkt->pfx,
				c->pkt->content, c->pkt->contlen, 0);

		if(!b){
			DEBUGMSG(ERROR, "content buffer could not be created!\n");
			return -1;
		}

		int i = b->datalen;
		memcpy(buf_out, b->data, i);
		*out_len=i;
		DEBUGMSG(TRACE, "output content size is %d\n", i);
    	return 1;
    }

    return 0;
}
