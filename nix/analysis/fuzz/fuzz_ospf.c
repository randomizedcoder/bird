/*
 *	libFuzzer harness: OSPFv2 and OSPFv3 packets.
 *
 *	Reachable from any host on an OSPF-enabled link (IP protocol 89):
 *	ospf_rx_hook() (address, length, checksum, area / instance / vlink
 *	dispatch, router ID and neighbour checks), authentication none, and
 *	all five packet types: Hello (neighbour and DR state), DBDES (master
 *	/ slave exchange, LSA header lists), LSR, LSU (lsa_validate() for
 *	every LSA type incl. OSPFv3 prefixes and extended TLVs, LSDB install,
 *	flooding, self-originated LSA handling) and LSAck. With the timer bit
 *	the clock moves on, so the dispatcher runs the SPF calculation over
 *	the installed LSAs (rt.c: intra-area, inter-area, external, NSSA
 *	translation), route import into BIRD's tables, LSA origination and
 *	aging, retransmissions and the hello / dead timers.
 *
 *	Two protocols on four fake interfaces (fuzz_iface.h), all
 *	point-to-point, BIRD as router 10.0.0.1, ABR in both:
 *	  0  o2  fz0  OSPFv2, area 0
 *	  1  o3  fz1  OSPFv3, area 0
 *	  2  o2  fz2  OSPFv2, area 1 (NSSA)
 *	  3  o3  fz3  OSPFv3, area 2 (stub)
 *	On each, the harness brings up a neighbour (router 10.0.<n>.2, at
 *	host 2 / fe80::2) the way a real router would: a Hello listing BIRD,
 *	then a DBDES exchange with the neighbour as master, until Full. LSR,
 *	LSU and LSAck are only accepted from a neighbour in Exchange or later,
 *	so the harness repeats the bring-up whenever an input drops it.
 *
 *	Input: one control byte, then the packet.
 *	  bits 0-1  interface (see above)
 *	  bit 2     destination: 0 = AllSPFRouters, 1 = BIRD (unicast)
 *	  bit 3     0 = packet type byte, then the body after the OSPF
 *	              header; the harness writes the header (version, type,
 *	              length, the neighbour's router ID, area, instance 0,
 *	              no authentication), the OSPFv2 checksum and, in LSUs,
 *	              each LSA's Fletcher checksum
 *	            1 = raw OSPF packet (from the version byte), no fix-ups
 *	  bit 4     keep LSA checksums as given (only with bit 3 clear)
 *	  bit 5     a time byte follows: afterwards, advance the clock by it
 *	            (fuzz_advance_byte()) and run the timers that are due
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "fuzz_sock.h"
#include "fuzz_iface.h"

#include "lib/checksum.h"
#include "proto/ospf/ospf.h"

#define FUZZ_OSPF_IFACES	4

#define FUZZ_OSPF_CONFIG						\
  "router id 10.0.0.1;\n"						\
  FUZZ_DEVICE_CONFIG							\
  "protocol ospf v2 o2 {\n"						\
  "  ipv4 { import all; export all; };\n"				\
  "  area 0 { interface \"fz0\" { type ptp; }; };\n"			\
  "  area 1 { nssa; summary yes; interface \"fz2\" { type ptp; }; };\n"	\
  "}\n"									\
  "protocol ospf v3 o3 {\n"						\
  "  ipv6 { import all; export all; };\n"				\
  "  area 0 { interface \"fz1\" { type ptp; }; };\n"			\
  "  area 2 { stub; interface \"fz3\" { type ptp; }; };\n"		\
  "}\n"

static struct ospf_proto *fuzz_p[2];
static struct ospf_iface *fuzz_ifa[FUZZ_OSPF_IFACES];
static u32 fuzz_ddseq = 0x10000;

/* IPv4 header (OSPFv2 raw socket) + the largest OSPF packet */
static byte fuzz_buf[20 + 65536];

static inline int fuzz_v2(uint i) { return !(i & 1); }
static inline u32 fuzz_nbr_rid(uint i) { return ipa_to_u32(FUZZ_IP4(i, 2)); }
static inline uint fuzz_hdrlen(uint i) { return fuzz_v2(i) ? 24 : 16; }

/* RFC 905 Annex B checksum of an LSA in network order (as
 * lsa_verify_checksum() checks it): over everything but the age field,
 * with the checksum at bytes 16-17. */
static void
fuzz_lsa_checksum(byte *lsa, uint len)
{
  int c0 = 0, c1 = 0;

  lsa[16] = lsa[17] = 0;
  for (uint i = 2; i < len; i++)
  {
    c0 = (c0 + lsa[i]) % 255;
    c1 = (c1 + c0) % 255;
  }

  int x = ((int) (len - 2 - 14 - 1) * c0 - c1) % 255;
  if (x <= 0)
    x += 255;
  int y = 510 - c0 - x;
  if (y > 255)
    y -= 255;

  lsa[16] = x;
  lsa[17] = y;
}

/* Fix every LSA checksum in an LSU (pkt at the OSPF header). */
static void
fuzz_lsu_checksums(uint i, byte *pkt, uint plen)
{
  uint pos = fuzz_hdrlen(i);

  if (plen < pos + 4)
    return;

  uint count = get_u32(pkt + pos);
  pos += 4;

  for (uint k = 0; (k < count) && (pos + 20 <= plen); k++)
  {
    uint len = get_u16(pkt + pos + 18);

    if ((len < 20) || (pos + len > plen))
      return;

    fuzz_lsa_checksum(pkt + pos, len);
    pos += len;
  }
}

/* Deliver an OSPF packet (pkt, plen: from the version byte) on interface i,
 * behind an IPv4 header for OSPFv2. */
static void
fuzz_ospf_feed(uint i, uint plen, int unicast)
{
  struct ospf_iface *ifa = fuzz_ifa[i];
  byte *ip = fuzz_buf;
  uint len = plen;
  struct fuzz_dgram d = { .iface = ifa->iface, .ttl = 1 };

  if (fuzz_v2(i))
  {
    ip[0] = 0x45;
    ip[1] = 0;
    put_u16(ip + 2, 20 + plen);
    put_u32(ip + 4, 0);
    ip[8] = 1;
    ip[9] = OSPF_PROTO;
    put_u16(ip + 10, 0);
    put_ip4(ip + 12, ipa_to_ip4(FUZZ_IP4(i, 2)));
    put_ip4(ip + 16, ipa_to_ip4(unicast ? ifa->addr->ip : ifa->all_routers));
    len += 20;

    d.faddr = FUZZ_IP4(i, 2);
  }
  else
  {
    memmove(fuzz_buf, fuzz_buf + 20, plen);
    d.faddr = FUZZ_LL6(2);
  }

  d.laddr = unicast ? ifa->addr->ip : ifa->all_routers;
  fuzz_sk_feed(ifa->sk, fuzz_buf, len, &d);
  fuzz_pump();
}

/* Header + checksum for the packet whose body is already at
 * fuzz_buf + 20 + hdrlen; returns the packet length. */
static uint
fuzz_ospf_header(uint i, uint type, uint blen, int fix_lsas)
{
  byte *pkt = fuzz_buf + 20;
  uint hlen = fuzz_hdrlen(i);
  uint plen = hlen + blen;
  struct ospf_iface *ifa = fuzz_ifa[i];

  pkt[0] = fuzz_v2(i) ? 2 : 3;			/* Version */
  pkt[1] = type;
  put_u16(pkt + 2, plen);
  put_u32(pkt + 4, fuzz_nbr_rid(i));
  put_u32(pkt + 8, ifa->oa->areaid);
  put_u16(pkt + 12, 0);
  pkt[14] = 0;				/* Instance ID / AuType high byte */
  pkt[15] = 0;				/* AuType: none */

  if (fuzz_v2(i))
    memset(pkt + 16, 0, 8);		/* Authentication data */

  if (fix_lsas && (type == LSUPD_P))
    fuzz_lsu_checksums(i, pkt, plen);

  /* Stored as computed, like ospf_pkt_finalize2() does */
  if (fuzz_v2(i))
  {
    u16 sum = ipsum_calculate(pkt, 16, pkt + hlen, blen, NULL);
    memcpy(pkt + 12, &sum, 2);
  }

  return plen;
}

/* ── Neighbour bring-up ─────────────────────────────────────────────── */

static struct ospf_neighbor *
fuzz_ospf_nbr(uint i)
{
  struct ospf_neighbor *n;

  WALK_LIST(n, fuzz_ifa[i]->neigh_list)
    if (n->rid == fuzz_nbr_rid(i))
      return n;

  return NULL;
}

static void
fuzz_ospf_hello(uint i)
{
  struct ospf_iface *ifa = fuzz_ifa[i];
  byte *b = fuzz_buf + 20 + fuzz_hdrlen(i);
  uint blen;

  if (fuzz_v2(i))
  {
    put_u32(b + 0, u32_mkmask(ifa->addr->prefix.pxlen));
    put_u16(b + 4, ifa->helloint);
    b[6] = ifa->oa->options;
    b[7] = 1;				/* Priority */
    put_u32(b + 8, ifa->deadint);
    put_u32(b + 12, 0);			/* DR */
    put_u32(b + 16, 0);			/* BDR */
    put_u32(b + 20, fuzz_p[0]->router_id);
    blen = 24;
  }
  else
  {
    put_u32(b + 0, 7);			/* Interface ID */
    put_u32(b + 4, (1 << 24) | (ifa->oa->options & 0x00ffffff));
    put_u16(b + 8, ifa->helloint);
    put_u16(b + 10, ifa->deadint);
    put_u32(b + 12, 0);
    put_u32(b + 16, 0);
    put_u32(b + 20, fuzz_p[1]->router_id);
    blen = 24;
  }

  fuzz_ospf_feed(i, fuzz_ospf_header(i, HELLO_P, blen, 0), 0);
}

static void
fuzz_ospf_dbdes(uint i, uint imms, u32 seq)
{
  struct ospf_iface *ifa = fuzz_ifa[i];
  byte *b = fuzz_buf + 20 + fuzz_hdrlen(i);

  if (fuzz_v2(i))
  {
    put_u16(b + 0, ifa->iface->mtu);
    b[2] = ifa->oa->options;
    b[3] = imms;
    put_u32(b + 4, seq);
  }
  else
  {
    put_u32(b + 0, ifa->oa->options & 0x00ffffff);
    put_u16(b + 4, ifa->iface->mtu);
    b[6] = 0;
    b[7] = imms;
    put_u32(b + 8, seq);
  }

  fuzz_ospf_feed(i, fuzz_ospf_header(i, DBDES_P, fuzz_v2(i) ? 8 : 12, 0), 1);
}

/* Hello, then DBDES as master until BIRD (slave) has nothing more. */
static int
fuzz_ospf_establish(uint i)
{
  struct ospf_neighbor *n;

  fuzz_ospf_hello(i);

  if (!(n = fuzz_ospf_nbr(i)) || (n->state != NEIGHBOR_EXSTART))
    return 0;

  u32 seq = fuzz_ddseq += 0x100;
  fuzz_ospf_dbdes(i, DBDES_IMMS, seq);

  for (int k = 0; k < 16; k++)
  {
    if (!(n = fuzz_ospf_nbr(i)) || (n->state < NEIGHBOR_EXCHANGE))
      return 0;
    if (n->state >= NEIGHBOR_LOADING)
      return 1;

    fuzz_ospf_dbdes(i, DBDES_MS, ++seq);
  }

  return 0;
}

static void
fuzz_setup(void)
{
  fuzz_bird_init(FUZZ_OSPF_CONFIG);

  fuzz_p[0] = (struct ospf_proto *) fuzz_proto_find(&proto_ospf, "o2");
  fuzz_p[1] = (struct ospf_proto *) fuzz_proto_find(&proto_ospf, "o3");

  for (uint i = 0; i < FUZZ_OSPF_IFACES; i++)
    fuzz_iface_add(i);

  /* The dispatcher originates the router LSAs; until an area has one,
   * BIRD does not answer a DBDES exchange (ospf_send_dbdes()). */
  fuzz_advance(2 S);

  for (uint i = 0; i < FUZZ_OSPF_IFACES; i++)
  {
    struct ospf_iface *ifa;

    WALK_LIST(ifa, fuzz_p[i & 1]->iface_list)
      if (ifa->iface && (ifa->iface->index == i + 2))
	fuzz_ifa[i] = ifa;

    if (!fuzz_ifa[i] || !fuzz_ifa[i]->sk)
    {
      fprintf(stderr, "fuzz: no OSPF interface on fz%u\n", i);
      abort();
    }

    if (!fuzz_ospf_establish(i))
    {
      struct ospf_neighbor *n = fuzz_ospf_nbr(i);
      fprintf(stderr, "fuzz: OSPF neighbour on fz%u not up (state %d)\n", i, n ? n->state : -1);
      abort();
    }
  }

  /* Past MinLSInterval: the router LSAs now carry the adjacencies, so
   * SPF over input LSAs reaches the neighbours. */
  fuzz_advance(6 S);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FUZZ_ONCE(fuzz_setup());

  uint8_t ctl = fuzz_take_byte(&data, &size);
  uint8_t dt = (ctl & 32) ? fuzz_take_byte(&data, &size) : 0;
  uint i = ctl & 3;
  uint plen;

  /* Past MinLSArrival, so an LSA a previous input installed can be
   * replaced (else every repeat is skipped); runs the timers due. */
  fuzz_advance(1 S);

  struct ospf_neighbor *n = fuzz_ospf_nbr(i);
  if (!n || (n->state < NEIGHBOR_EXCHANGE))
    fuzz_ospf_establish(i);

  if (ctl & 8)
  {
    if (size > sizeof(fuzz_buf) - 20)
      return 0;
    memcpy(fuzz_buf + 20, data, size);
    plen = size;
  }
  else
  {
    uint type = fuzz_take_byte(&data, &size);

    if (size > sizeof(fuzz_buf) - 20 - fuzz_hdrlen(i))
      return 0;
    memcpy(fuzz_buf + 20 + fuzz_hdrlen(i), data, size);
    plen = fuzz_ospf_header(i, type, size, !(ctl & 16));
  }

  fuzz_ospf_feed(i, plen, ctl & 4);

  if (ctl & 32)
    fuzz_advance_byte(dt);

  return 0;
}
