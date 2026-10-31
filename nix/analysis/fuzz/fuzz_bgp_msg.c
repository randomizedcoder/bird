/*
 *	libFuzzer harness: BGP messages on an Established session.
 *
 *	Reachable from any configured BGP neighbor once the session is up:
 *	bgp_rx() framing, UPDATE (bgp_decode_attrs(), every attribute
 *	decoder in attrs.c, MP_REACH/MP_UNREACH, the NLRI and next-hop
 *	decoders for all 13 AFI/SAFIs incl. flowspec and EVPN, ADD-PATH,
 *	MPLS labels, extended next hop), then route import into the tables
 *	(rta caching, hostentry resolution, flowspec validation), plus
 *	ROUTE-REFRESH/BoRR/EoRR, KEEPALIVE and NOTIFICATION.
 *
 *	Input: one control byte, then the message body.
 *	  bit 0     session: 0 = eBGP, 1 = iBGP (route reflector client)
 *	  bits 1-2  0, 1: UPDATE body (header added by the harness)
 *	            2:    ROUTE-REFRESH body
 *	            3:    raw byte stream, framed by the input itself
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "fuzz_bgp_common.h"

static struct bgp_proto *fuzz_p[2];
static struct bgp_conn *fuzz_conn[2];
static byte fuzz_buf[BGP_RX_BUFFER_EXT_SIZE];

static void
fuzz_setup(void)
{
  char *cfg = malloc(strlen(fuzz_log_config()) + sizeof(FUZZ_BGP_CONFIG));

  strcpy(cfg, fuzz_log_config());
  strcat(cfg, FUZZ_BGP_CONFIG);
  fuzz_bird_init(cfg);

  fuzz_p[0] = fuzz_bgp_find("peer_e");
  fuzz_p[1] = fuzz_bgp_find("peer_i");

  for (int i = 0; i < 2; i++)
    fuzz_conn[i] = fuzz_bgp_connect(fuzz_p[i]);

  fuzz_bgp_establish(fuzz_p[0], fuzz_conn[0], FUZZ_BGP_EBGP_AS, 0xc0000202);
  fuzz_bgp_establish(fuzz_p[1], fuzz_conn[1], FUZZ_BGP_IBGP_AS, 0xc0000203);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FUZZ_ONCE(fuzz_setup());

  uint8_t ctl = fuzz_take_byte(&data, &size);
  struct bgp_conn *conn = fuzz_conn[ctl & 1];
  uint mode = (ctl >> 1) & 3;
  uint len;

  if (mode == 3)
  {
    if (size > sizeof(fuzz_buf))
      return 0;
    memcpy(fuzz_buf, data, size);
    len = size;
  }
  else
  {
    if (size > sizeof(fuzz_buf) - BGP_HEADER_LENGTH)
      return 0;
    len = BGP_HEADER_LENGTH + size;
    fuzz_bgp_header(fuzz_buf, len, (mode == 2) ? PKT_ROUTE_REFRESH : PKT_UPDATE);
    memcpy(fuzz_buf + BGP_HEADER_LENGTH, data, size);
  }

  fuzz_bgp_feed(conn, fuzz_buf, len);
  fuzz_pump();

  /* Errors close the connection; reopen it for the next input. */
  conn->state = BS_ESTABLISHED;

  return 0;
}
