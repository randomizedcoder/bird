/*
 *	libFuzzer harness: flowspec NLRI (RFC 8955/8956) in lib/flowspec.c.
 *
 *	The same steps bgp_decode_nlri_flow4/6() run on every received
 *	flow NLRI: flow4/6_decode() (validate + normalize in place), dst
 *	prefix extraction and net_fill_flow4/6(). For NLRIs that decode,
 *	everything that later walks the stored net: the part iterators,
 *	flow4/6_net_format() (logging, `show route`) into a full and a short
 *	buffer, net_hash() and net_validate().
 *
 *	Oracle: a decoded (normalized) NLRI must pass flow4/6_validate();
 *	a mismatch aborts.
 *
 *	Input: one control byte, then the NLRI components (no length
 *	header; the harness adds it, as it precedes them on the wire).
 *	  bit 0  0: IPv4 flowspec, 1: IPv6 flowspec
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "fuzz_bird.h"

#include "lib/net.h"
#include "lib/flowspec.h"

static void
fuzz_walk(const net_addr *n, int ipv6)
{
  const byte *end = (const byte *) n + n->length;
  const byte *pos = ipv6 ? flow6_first_part((const net_addr_flow6 *) n) :
    flow4_first_part((const net_addr_flow4 *) n);

  for (; pos && pos < end; pos = ipv6 ? flow6_next_part(pos, end) : flow4_next_part(pos, end))
    if (*pos == FLOW_TYPE_DST_PREFIX || *pos == FLOW_TYPE_SRC_PREFIX)
    {
      if (ipv6)
	(void) flow_read_ip6_part(pos);
      else
	(void) flow_read_ip4_part(pos);
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FUZZ_ONCE(fuzz_bird_init(NULL));

  int ipv6 = fuzz_take_byte(&data, &size) & 1;
  char out[4096];

  /* The length header encodes at most 0xfff (RFC 8955 4.1). */
  if (size > 0xfff)
    return 0;

  /* Wire layout: length header, then components. */
  uint hlen = (size < 0xf0) ? 1 : 2;
  uint flen = hlen + size;
  byte *nlri = malloc(flen);
  flow_write_length(nlri, size);
  memcpy(nlri + hlen, data, size);

  byte *comp = nlri + flow_hdr_length(nlri);
  uint dlen = flow_read_length(nlri);

  enum flow_validated_state r = ipv6 ? flow6_decode(comp, dlen) : flow4_decode(comp, dlen);
  if (r != FLOW_ST_VALID)
    goto done;

  r = ipv6 ? flow6_validate(comp, dlen) : flow4_validate(comp, dlen);
  if (r != FLOW_ST_VALID)
  {
    fprintf(stderr, "fuzz: decoded flow%c NLRI fails validation: %s\n",
	    ipv6 ? '6' : '4', flow_validated_state_str(r));
    abort();
  }

  net_addr *n = alloca(sizeof(net_addr_flow6) + flen);
  if (!ipv6)
  {
    ip4_addr px = IP4_NONE;
    uint pxlen = 0;
    if (dlen && (comp[0] == FLOW_TYPE_DST_PREFIX))
    {
      px = flow_read_ip4_part(comp);
      pxlen = flow_read_pxlen(comp);
    }
    net_fill_flow4(n, px, pxlen, nlri, flen);
    flow4_net_format(out, sizeof(out), (net_addr_flow4 *) n);
    flow4_net_format(out, 32, (net_addr_flow4 *) n);
  }
  else
  {
    ip6_addr px = IP6_NONE;
    uint pxlen = 0;
    if (dlen && (comp[0] == FLOW_TYPE_DST_PREFIX))
    {
      px = flow_read_ip6_part(comp);
      pxlen = flow_read_pxlen(comp);
    }
    net_fill_flow6(n, px, pxlen, nlri, flen);
    flow6_net_format(out, sizeof(out), (net_addr_flow6 *) n);
    flow6_net_format(out, 32, (net_addr_flow6 *) n);
  }

  fuzz_walk(n, ipv6);
  (void) net_hash(n);
  (void) net_validate(n);

done:
  free(nlri);
  return 0;
}
