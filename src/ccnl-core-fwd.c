 /*
 * @f ccnl-core-fwd.c
 * @b CCN lite, the collection of suite specific forwarding logics
 *
 * Copyright (C) 2011-15, Christian Tschudin, University of Basel
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
 * 2014-11-05 collected from the various fwd-XXX.c files
 */

// returning 0 if packet was 
int
ccnl_fwd_handleContent(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                       struct ccnl_pkt_s **pkt)
{
    struct ccnl_content_s *c;

    DEBUGMSG_CFWD(DEBUG, "  data=<%s>\n", ccnl_prefix_to_path((*pkt)->pfx));

#if defined(USE_SUITE_CCNB) && defined(USE_SIGNATURES)
//  FIXME: mgmt messages for NDN and other suites?
        if (pkt->pfx->compcnt == 2 && !memcmp(pkt->pfx->comp[0], "ccnx", 4)
                && !memcmp(pkt->pfx->comp[1], "crypto", 6) &&
                from == relay->crypto_face) {
            return ccnl_crypto(relay, pkt->buf, pkt->pfx, from);
        }
#endif /* USE_SUITE_CCNB && USE_SIGNATURES*/

    // CONFORM: Step 1:
    for (c = relay->contents; c; c = c->next)
        if (buf_equal(c->pkt->buf, (*pkt)->buf))
            return 0; // content is dup, do nothing

    c = ccnl_content_new(relay, pkt);
    if (!c)
        return 0;

     // CONFORM: Step 2 (and 3)
#ifdef USE_NFN
    if (ccnl_nfnprefix_isNFN(c->pkt->pfx)) {
        if (ccnl_nfn_RX_result(relay, from, c))
            return 0;
        DEBUGMSG_CFWD(VERBOSE, "no running computation found \n");
    }
#endif
    if (!ccnl_content_serve_pending(relay, c)) { // unsolicited content
        // CONFORM: "A node MUST NOT forward unsolicited data [...]"
        DEBUGMSG_CFWD(DEBUG, "  removed because no matching interest\n");
        free_content(c);
        return 0;
    }
    if (relay->max_cache_entries != 0) { // it's set to -1 or a limit
        DEBUGMSG_CFWD(DEBUG, "  adding content to cache\n");
        ccnl_content_add2cache(relay, c);
    } else {
        DEBUGMSG_CFWD(DEBUG, "  content not added to cache\n");
        free_content(c);
    }
    return 0;
}

// ----------------------------------------------------------------------
// returns 0 if packet should not be forwarded further
int
ccnl_pkt_fwdOK(struct ccnl_pkt_s *pkt)
{
    switch (pkt->suite) {
#ifdef USE_SUITE_IOTTLV
    case CCNL_SUITE_IOTTLV:
        return pkt->s.iottlv.ttl < 0 || pkt->s.iottlv.ttl > 0;
#endif
#ifdef USE_SUITE_NDNTLV
    case CCNL_SUITE_NDNTLV:
        return pkt->s.ndntlv.scope > 2;
#endif
    default:
        break;
    }

    return -1;
}

int
ccnl_fwd_handleInterest(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                        struct ccnl_pkt_s **pkt, cMatchFct cMatch)
{
    struct ccnl_interest_s *i;
    struct ccnl_content_s *c;

    DEBUGMSG_CFWD(DEBUG, "  handle interest=<%s>\n",
                  ccnl_prefix_to_path((*pkt)->pfx));
    if (ccnl_nonce_isDup(relay, *pkt)) {
        DEBUGMSG_CFWD(DEBUG, "  dropped because of duplicate nonce\n");
        return 0;
    }

    if (local_producer(relay, from, *pkt)) {
        *pkt = NULL;
        return 0;
    }

#ifdef USE_SUITE_CCNB
    if ((*pkt)->suite == CCNL_SUITE_CCNB && (*pkt)->pfx->compcnt == 4 &&
                                  !memcmp((*pkt)->pfx->comp[0], "ccnx", 4)) {
        DEBUGMSG_CFWD(INFO, "  found a mgmt message\n");
        ccnl_mgmt(relay, (*pkt)->buf, (*pkt)->pfx, from); // use return value?
        return 0;
    }
#endif
    // Step 1: search in content store
    DEBUGMSG_CFWD(DEBUG, "  searching in CS\n");

    for (c = relay->contents; c; c = c->next) {
        if (c->pkt->pfx->suite != (*pkt)->pfx->suite)
            continue;
        if (cMatch(*pkt, c))
            continue;

        DEBUGMSG_CFWD(DEBUG, "  found matching content %p\n", (void *) c);
        if (from->ifndx >= 0) {
            ccnl_nfn_monitor(relay, from, c->pkt->pfx, c->pkt->content,
                             c->pkt->contlen);
            ccnl_face_enqueue(relay, from, buf_dup(c->pkt->buf));
        } else {
            ccnl_app_RX(relay, c);
        }
        return 0; // we are done
    }

    // CONFORM: Step 2: check whether interest is already known
#ifdef USE_KITE
    if ((*pkt)->tracing) { // is a tracing interest
        for (i = relay->pit; i; i = i->next) {
        }
    }
#endif
    for (i = relay->pit; i; i = i->next)
        if (ccnl_interest_isSame(i, *pkt))
            break;
        
    if (!i) { // this is a new/unknown I request: create and propagate
#ifdef USE_NFN
        if (ccnl_nfn_RX_request(relay, from, pkt))
            return -1; // this means: everything is ok and pkt was consumed
#endif
    }
    if (!ccnl_pkt_fwdOK(*pkt))
        return -1;
    if (!i) {
        i = ccnl_interest_new(relay, from, pkt);
        DEBUGMSG_CFWD(DEBUG,
            "  created new interest entry %p\n", (void *) i);
    }
    if (i) { // store the I request, for the incoming face (Step 3)
        DEBUGMSG_CFWD(DEBUG, "  appending interest entry %p\n", (void *) i);
        ccnl_interest_append_pending(i, from);
        ccnl_interest_propagate(relay, i);
    }
        
    /*
    if (!i) { // this is a new/unknown I request: create and propagate
#ifdef USE_NFN
        if (ccnl_nfn_RX_request(relay, from, pkt))
            return -1; // this means: everything is ok and pkt was consumed
#endif
<<<<<<< HEAD
        if (!ccnl_pkt_fwdOK(*pkt))
            return -1;
        i = ccnl_interest_new(relay, from, pkt);
        DEBUGMSG_CFWD(DEBUG,
            "  created new interest entry %p\n", (void *) i);
        ccnl_interest_propagate(relay, i);
    } else {
        if (ccnl_pkt_fwdOK(*pkt) && (from->flags & CCNL_FACE_FLAGS_FWDALLI)) {
            DEBUGMSG_CFWD(DEBUG, "  old interest, nevertheless propagated %p\n",
                     (void *) i);
            ccnl_interest_propagate(relay, i);
=======
        if (!i) {
            i = ccnl_interest_new(ccnl, from, CCNL_SUITE_CCNB,
                                  &buf, &p, minsfx, maxsfx);
            if (ppkd)
                i->details.ccnb.ppkd = ppkd, ppkd = NULL;
            if (i) { // CONFORM: Step 3 (and 4)
                DEBUGMSG_CFWD(DEBUG, "  created new interest entry %p\n", (void *)i);
                if (scope > 2)
                    ccnl_interest_propagate(ccnl, i);
            }
        } else if (scope > 2 && (from->flags & CCNL_FACE_FLAGS_FWDALLI)) {
            DEBUGMSG_CFWD(DEBUG, "  old interest, nevertheless propagated %p\n",
                     (void *) i);
            ccnl_interest_propagate(ccnl, i);
        }
        if (i) { // store the I request, for the incoming face (Step 3)
            DEBUGMSG_CFWD(DEBUG, "  appending interest entry %p\n", (void *) i);
            ccnl_interest_append_pending(i, from);
>>>>>>> origin/arduino
        }
    }
    if (i) { // store the I request, for the incoming face (Step 3)
        DEBUGMSG_CFWD(DEBUG, "  appending interest entry %p\n", (void *) i);
        ccnl_interest_append_pending(i, from);
    }
    */
    return 0;
}

// ----------------------------------------------------------------------

#ifdef USE_SUITE_CCNB

// helper proc: work on a message, top level type is already stripped
int
ccnl_ccnb_fwd(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
              unsigned char **data, int *datalen, int typ)
{
    int rc= -1;
    struct ccnl_pkt_s *pkt;

    DEBUGMSG_CFWD(DEBUG, "ccnb fwd (%d bytes left)\n", *datalen);

    pkt = ccnl_ccnb_bytes2pkt(*data - 2, data, datalen);
    if (!pkt) {
        DEBUGMSG_CFWD(WARNING, "  parsing error or no prefix\n");
        goto Done;
    }
    pkt->type = typ;
    pkt->flags |= typ == CCN_DTAG_INTEREST ? CCNL_PKT_REQUEST : CCNL_PKT_REPLY;

    if (pkt->flags & CCNL_PKT_REQUEST) { // interest
        if (ccnl_fwd_handleInterest(relay, from, &pkt, ccnl_ccnb_cMatch))
            goto Done;
    } else { // content
        if (ccnl_fwd_handleContent(relay, from, &pkt))
            goto Done;
    }
    rc = 0;
Done:
    free_packet(pkt);
    return rc;
}

// loops over a frame until empty or error
int
ccnl_ccnb_forwarder(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                    unsigned char **data, int *datalen)
{
    int rc = 0, num, typ;
    DEBUGMSG_CFWD(DEBUG, "ccnl_ccnb_forwarder: %dB from face=%p (id=%d.%d)\n",
             *datalen, (void*)from, relay->id, from ? from->faceid : -1);

    while (rc >= 0 && *datalen > 0) {
        if (ccnl_ccnb_dehead(data, datalen, &num, &typ) || typ != CCN_TT_DTAG)
            return -1;
        switch (num) {
        case CCN_DTAG_INTEREST:
        case CCN_DTAG_CONTENTOBJ:
            rc = ccnl_ccnb_fwd(relay, from, data, datalen, num);
            continue;
#ifdef USE_FRAG
        case CCNL_DTAG_FRAGMENT2012:
            rc = ccnl_frag_RX_frag2012(ccnl_ccnb_forwarder, relay,
                                       from, data, datalen);
            continue;
        case CCNL_DTAG_FRAGMENT2013:
            rc = ccnl_frag_RX_CCNx2013(ccnl_ccnb_forwarder, relay,
                                       from, data, datalen);
            continue;
#endif
        default:
            DEBUGMSG_CFWD(DEBUG, "  unknown datagram type %d\n", num);
            return -1;
        }
    }
    return rc;
}

#endif // USE_SUITE_CCNB

// ----------------------------------------------------------------------

#ifdef USE_SUITE_CCNTLV

// process one CCNTLV packet, return <0 if no bytes consumed or error
int
ccnl_ccntlv_forwarder(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                      unsigned char **data, int *datalen)
{
    int payloadlen, rc = -1;
    unsigned short hdrlen;
    struct ccnx_tlvhdr_ccnx2015_s *hp;
    unsigned char *start = *data;
    struct ccnl_pkt_s *pkt;

    DEBUGMSG_CFWD(DEBUG, "ccnl_ccntlv_forwarder: %dB from face=%p (id=%d.%d)\n",
                  *datalen, (void*)from, relay->id, from ? from->faceid : -1);

    if (**data != CCNX_TLV_V1 ||
                         *datalen < sizeof(struct ccnx_tlvhdr_ccnx2015_s)) {
        DEBUGMSG_CFWD(DEBUG, "  wrong version (%d)\n", **data);
        return -1;
    }

    hp = (struct ccnx_tlvhdr_ccnx2015_s*) *data;
    hdrlen = hp->hdrlen; // ntohs(hp->hdrlen);
fprintf(stderr, "------ hdrlen=%d\n", hdrlen);
    if (hdrlen > *datalen) { // not enough bytes for a full header
        DEBUGMSG_CFWD(DEBUG, "  hdrlen too large (%d > %d)\n",
                      hdrlen, *datalen);
        return -1;
    }

    payloadlen = ntohs(hp->pktlen);
    if (payloadlen < hdrlen ||
             payloadlen > *datalen) { // not enough data to reconstruct message
        DEBUGMSG_CFWD(DEBUG, "  pkt too small or too big (%d < %d < %d)\n",
                 hdrlen, payloadlen, *datalen);
        return -1;
    }
    payloadlen -= hdrlen;

    *data += hdrlen;
    *datalen -= hdrlen;

    if (hp->pkttype == CCNX_PT_Interest ||
#ifdef USE_FRAG
        hp->pkttype == CCNX_PT_FRAGMENT ||
#endif
                                        hp->pkttype == CCNX_PT_NACK) {
        hp->hoplimit--;
        if (hp->hoplimit <= 0) { // drop it
            DEBUGMSG_CFWD(DEBUG, "  pkt dropped because of hop limit\n");
            *data += payloadlen;
            *datalen -= payloadlen;
            return 0;
        }
    }

    DEBUGMSG_CFWD(DEBUG, "ccnl_ccntlv_forwarder (%d bytes left, hdrlen=%d)\n",
                  *datalen, hdrlen);

#ifdef USE_FRAG
    if (hp->pkttype == CCNX_PT_FRAGMENT) {
        struct ccnx_tlvhdr_ccnx2015_s *fp = 
                                   (struct ccnx_tlvhdr_ccnx2015_s *)hp;
        uint16_t *sp = (uint16_t*) (fp+1);
        int fraglen = ntohs(*(sp+1));

        if (ntohs(*sp) == CCNX_TLV_TL_Fragment && fraglen == (payloadlen-4)) {
            *data += 4;
            *datalen -= 4;
            payloadlen = fraglen;
            ccnl_frag_RX_CCNx2015(ccnl_ccntlv_forwarder, relay, from,
                        fp->fill[0] >> 6,
                        ntohs(*(uint16_t *)fp->fill) & 0x03fff,
                        data, &fraglen);
            DEBUGMSG_CFWD(DEBUG, "  done (fraglen=%d, payloadlen=%d, *datalen=%d)\n",
                     fraglen, payloadlen, *datalen);
            *datalen -= payloadlen - fraglen;
        } else {
            DEBUGMSG_CFWD(DEBUG, "  problem with frag type or length (%d, %d, %d)\n",
                     ntohs(*sp), fraglen, payloadlen);
            *data += payloadlen;
            *datalen -= payloadlen;
        }
        DEBUGMSG_CFWD(TRACE, "  returning after fragment: %d bytes\n", *datalen);
        return 0;
    }
#endif

    pkt = ccnl_ccntlv_bytes2pkt(start, data, datalen);
    if (!pkt) {
        DEBUGMSG_CFWD(WARNING, "  parsing error or no prefix\n");
        goto Done;
    }

    if (hp->pkttype == CCNX_PT_Interest) {
        if (pkt->type == CCNX_TLV_TL_Interest) {
            pkt->flags |= CCNL_PKT_REQUEST;
            // DEBUGMSG_CFWD(DEBUG, "  interest=<%s>\n", ccnl_prefix_to_path(pkt->pfx));
            if (ccnl_fwd_handleInterest(relay, from, &pkt, ccnl_ccntlv_cMatch))
                goto Done;
        } else {
            DEBUGMSG_CFWD(WARNING, "  ccntlv: interest pkt type mismatch %d %d\n",
                          hp->pkttype, pkt->type);
        }
    } else if (hp->pkttype == CCNX_PT_Data) {
        if (pkt->type == CCNX_TLV_TL_Object) {
            pkt->flags |= CCNL_PKT_REPLY;
            ccnl_fwd_handleContent(relay, from, &pkt);
        } else {
            DEBUGMSG_CFWD(WARNING, "  ccntlv: data pkt type mismatch %d %d\n",
                     hp->pkttype, pkt->type);
        }
    } // else ignore
    rc = 0;
Done:
    free_packet(pkt);

    DEBUGMSG_CFWD(TRACE, "  returning %d bytes\n", *datalen);
    return rc;
}

#endif // USE_SUITE_CCNTLV

// ----------------------------------------------------------------------

#ifdef USE_SUITE_CISTLV

// process one CISTLV packet, return <0 if no bytes consumed or error
int
ccnl_cistlv_forwarder(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                      unsigned char **data, int *datalen)
{
    int payloadlen, hoplimit, rc = -1;
    unsigned short hdrlen;
    struct cisco_tlvhdr_201501_s *hp;
    unsigned char *start = *data;
    struct ccnl_pkt_s *pkt;

    DEBUGMSG_CFWD(DEBUG, "ccnl_RX_ccntlv: %d bytes from face=%p (id=%d.%d)\n",
             *datalen, (void*)from, relay->id, from ? from->faceid : -1);

    if (**data != CISCO_TLV_V1 ||
                        *datalen < sizeof(struct cisco_tlvhdr_201501_s))
        return -1;

    hp = (struct cisco_tlvhdr_201501_s*) *data;
    hdrlen = hp->hlen;
    if (hdrlen > *datalen) // not enough bytes for a full header
        return -1;

    payloadlen = ntohs(hp->pktlen);
    if (payloadlen < hdrlen ||
              payloadlen > *datalen) // not enough data to reconstruct message
            return -1;
    payloadlen -= hdrlen;

    *data += hdrlen;
    *datalen -= hdrlen;

    hoplimit = hp->hoplim - 1;
    if (hp->pkttype == CISCO_PT_Interest && hoplimit <= 0) { // drop it
        *data += payloadlen;
        *datalen -= payloadlen;
        return 0;
    } else
        hp->hoplim = hoplimit;

    DEBUGMSG_CFWD(DEBUG, "ccnl_cistlv_forwarder (%d bytes left, hdrlen=%d)\n",
             *datalen, hdrlen);

    pkt = ccnl_cistlv_bytes2pkt(start, data, datalen);
    if (!pkt) {
        DEBUGMSG_CFWD(WARNING, "  parsing error or no prefix\n");
        goto Done;
    }

    if (hp->pkttype == CISCO_PT_Interest) {
        if (pkt->type == CISCO_TLV_Interest) {
            pkt->flags |= CCNL_PKT_REQUEST;
            //            DEBUGMSG_CFWD(DEBUG, "  interest=<%s>\n", ccnl_prefix_to_path(pkt->pfx));
            if (ccnl_fwd_handleInterest(relay, from, &pkt, ccnl_cistlv_cMatch))
                goto Done;
        } else {
            DEBUGMSG_CFWD(WARNING, "  cistlv: interest pkt type mismatch %d %d\n",
                     hp->pkttype, pkt->type);
        }

    } else if (hp->pkttype == CISCO_PT_Content) {
        if (pkt->type == CISCO_TLV_Content) {
            pkt->flags |= CCNL_PKT_REPLY;
            ccnl_fwd_handleContent(relay, from, &pkt);
        } else {
            DEBUGMSG_CFWD(WARNING, "  cistlv: data pkt type mismatch %d %d\n",
                     hp->pkttype, pkt->type);
        }
    } // else ignore (Nack...)
    rc = 0;
Done:
    free_packet(pkt);

    return rc;
}

#endif // USE_SUITE_CISTLV

// ----------------------------------------------------------------------

#ifdef USE_SUITE_IOTTLV

// process one IOTTLV packet, return <0 if no bytes consumed or error
int
ccnl_iottlv_forwarder(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                      unsigned char **data, int *datalen)
{
    int typ, len, rc = -1, enc;
    unsigned char *start = *data;
    struct ccnl_pkt_s *pkt;

    DEBUGMSG_CFWD(TRACE, "ccnl_iottlv_forwarder: %dB from face=%p (id=%d.%d)\n",
             *datalen, (void*)from, relay->id, from ? from->faceid : -1);
    /*
    {
        int fd = open("t.bin", O_WRONLY|O_CREAT|O_TRUNC);
        write(fd, *data, *datalen);
        close(fd);
    }
    */
    while (!ccnl_switch_dehead(data, datalen, &enc));
/*
        suite = ccnl_enc2suite(enc);
    if (suite != CCNL_SUITE_IOTTLV) {
        DEBUGMSG_CFWD(TRACE, "  wrong encoding? (%d)\n", enc);
        return -1;
    }
*/


    DEBUGMSG_CFWD(TRACE, "  datalen now %d\n", *datalen);

#ifdef USE_FRAG
    if (ccnl_iottlv_peekType(*data, *datalen) == IOT_TLV_Fragment) {
        uint16_t tmp;
        int payloadlen;

        if (ccnl_iottlv_dehead(data, datalen, &typ, &len)) // IOT_TLV_Fragment
            return -1;
        if (ccnl_iottlv_dehead(data, datalen, &typ, &len))
            return -1;
        if (typ == IOT_TLV_F_OptFragHdr) { // skip it for the time being
            *data += len;
            *datalen -= len;
            if (ccnl_iottlv_dehead(data, datalen, &typ, &len))
                return -1;
        }
        if (typ != IOT_TLV_F_FlagsAndSeq || len < 2) {
            DEBUGMSG_CFWD(DEBUG, "  no flags and seqrn found (%d)\n", typ);
            return -1;
        }
        tmp = ntohs(*(uint16_t*) *data);
        *data += len;
        *datalen -= len;

        if (ccnl_iottlv_dehead(data, datalen, &typ, &payloadlen))
            return -1;
        if (typ != IOT_TLV_F_Payload) {
            DEBUGMSG_CFWD(DEBUG, "  no payload (%d)\n", typ);
            return -1;
        }
        *datalen -= payloadlen;
        ccnl_frag_RX_CCNx2015(ccnl_iottlv_forwarder, relay, from,
                              tmp >> 14, tmp & 0x7ff, data, &payloadlen);
        *datalen += payloadlen;

        DEBUGMSG_CFWD(TRACE, "  returning after fragment: %d bytes\n", *datalen);
        return 0;
    } else
#endif
        if (ccnl_iottlv_dehead(data, datalen, &typ, &len)) // IOT_TLV_Fragment
            return -1;

    pkt = ccnl_iottlv_bytes2pkt(start, data, datalen);
    if (!pkt) {
        DEBUGMSG_CFWD(WARNING, "  parsing error or no prefix\n");
        goto Done;
    }

    DEBUGMSG_CFWD(DEBUG, "  parsed packet has %d bytes\n", pkt->buf->datalen);
    // typ must be Request or Reply
    pkt->type = typ;

    if (typ == IOT_TLV_Request) {
        pkt->flags |= CCNL_PKT_REQUEST;
        if (ccnl_fwd_handleInterest(relay, from, &pkt, ccnl_iottlv_cMatch))
            goto Done;
    } else { // data packet with content -------------------------------------
        pkt->flags |= CCNL_PKT_REPLY;
        if (ccnl_fwd_handleContent(relay, from, &pkt))
            goto Done;
    }
    rc = 0;
Done:
    free_packet(pkt);
    return rc;
}

#endif // USE_SUITE_IOTTLV

// ----------------------------------------------------------------------

#ifdef USE_SUITE_NDNTLV

// process one NDNTLV packet, return <0 if no bytes consumed or error
int
ccnl_ndntlv_forwarder(struct ccnl_relay_s *relay, struct ccnl_face_s *from,
                      unsigned char **data, int *datalen)
{
    int typ, len, rc = -1;
    unsigned char *start = *data;
    struct ccnl_pkt_s *pkt;

    DEBUGMSG_CFWD(DEBUG, "ccnl_ndntlv_forwarder (%d bytes left)\n", *datalen);
    DEBUGMSG_CFWD(INFO, "  packet starts with %02x %02x %02x\n",
                  (*data)[0], (*data)[1], (*data)[2]);

    if (ccnl_ndntlv_dehead(data, datalen, &typ, &len) || len > *datalen) {
        DEBUGMSG_CFWD(TRACE, "  invalid packet format\n");
        return -1;
    }
    pkt = ccnl_ndntlv_bytes2pkt(start, data, datalen);
    if (!pkt) {
        DEBUGMSG_CFWD(DEBUG, "  parsing error or no prefix\n");
        goto Done;
    }
    pkt->type = typ;
    if (typ == NDN_TLV_Interest) {
        pkt->flags |= CCNL_PKT_REQUEST;
        if (ccnl_fwd_handleInterest(relay, from, &pkt, ccnl_ndntlv_cMatch))
            goto Done;
    } else { // data packet with content -------------------------------------
        pkt->flags |= CCNL_PKT_REPLY;
        if (ccnl_fwd_handleContent(relay, from, &pkt))
            goto Done;
    }
    rc = 0;
Done:
    free_packet(pkt);
    return rc;
}

#endif // USE_SUITE_NDNTLV

// eof
