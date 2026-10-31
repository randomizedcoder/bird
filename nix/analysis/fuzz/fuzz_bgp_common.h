/*
 *	BGP session setup shared by fuzz_bgp_open and fuzz_bgp_msg.
 *
 *	The real configuration and startup path runs: the config below is
 *	parsed and committed, each protocol takes its object lock, waits out
 *	its connect delay and calls sk_open() on an active TCP socket. Only
 *	the socket layer is stubbed, with -Wl,--wrap (fuzz.mk):
 *
 *	  sk_open()   allocates the buffers, opens no descriptor
 *	  sk_send()   reports the data as sent
 *
 *	fuzz_bgp_connect() then fires the socket's tx_hook (bgp_connected:
 *	send OPEN, enter OpenSent), and fuzz_bgp_establish() feeds a peer
 *	OPEN carrying every capability BIRD implements and a KEEPALIVE
 *	through bgp_rx(), so the session reaches Established with all
 *	channels up exactly as with a real peer.
 *
 *	Errors raised while parsing fuzz input (bgp_error() and the close
 *	paths, called from packets.c) are wrapped too: they record the
 *	error and mark the connection closed, which stops bgp_rx() the way
 *	the real ones do, but the session is kept so the next input starts
 *	from the same state. --wrap only redirects calls between objects,
 *	so bgp.c's own internal calls are unaffected.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_NIX_FUZZ_BGP_COMMON_H_
#define _BIRD_NIX_FUZZ_BGP_COMMON_H_

#include "fuzz_bird.h"

#include "nest/protocol.h"
#include "lib/socket.h"
#include "nest/attrs.h"
#include "proto/bgp/bgp.h"

extern list proto_list;

/*
 * Two sessions: eBGP (65000 <-> 65001) and iBGP (65000, peer is a route
 * reflector client), so attributes valid only on one kind (LOCAL_PREF,
 * ORIGINATOR_ID, CLUSTER_LIST, AS_PATH first-AS checks) take both paths.
 * Every AFI/SAFI the BGP code implements has a channel.
 */
#define FUZZ_BGP_CONFIG							\
  "router id 192.0.2.1;\n"						\
  "ipv4 table mc4;\n"							\
  "ipv6 table mc6;\n"							\
  "vpn4 table vpntab4;\n"						\
  "vpn6 table vpntab6;\n"						\
  "vpn4 table vpnmc4;\n"						\
  "vpn6 table vpnmc6;\n"						\
  "flow4 table flowtab4;\n"						\
  "flow6 table flowtab6;\n"						\
  "evpn table evpntab;\n"						\
  "ipv4 table lab4;\n"							\
  "ipv6 table lab6;\n"							\
  "mpls domain mdom;\n"							\
  "mpls table mtab;\n"							\
  "template bgp fz {\n"							\
  "  local 192.0.2.1 as 65000;\n"					\
  "  multihop;\n"							\
  "  connect delay time 1;\n"						\
  "  enable extended messages on;\n"					\
  "  graceful restart on;\n"						\
  "  long lived graceful restart on;\n"				\
  "  mpls { domain mdom; table mtab; label policy aggregate; };\n"	\
  "  ipv4 { import all; export none; add paths on; extended next hop on; };\n" \
  "  ipv6 { import all; export none; add paths on; };\n"		\
  "  ipv4 multicast { table mc4; import all; export none; add paths on; };\n" \
  "  ipv6 multicast { table mc6; import all; export none; add paths on; };\n" \
  "  ipv4 mpls { table lab4; import all; export none; add paths on; };\n" \
  "  ipv6 mpls { table lab6; import all; export none; add paths on; };\n" \
  "  vpn4 mpls { table vpntab4; import all; export none; add paths on; };\n" \
  "  vpn6 mpls { table vpntab6; import all; export none; add paths on; };\n" \
  "  vpn4 multicast { table vpnmc4; import all; export none; };\n"	\
  "  vpn6 multicast { table vpnmc6; import all; export none; };\n"	\
  "  flow4 { table flowtab4; import all; export none; };\n"		\
  "  flow6 { table flowtab6; import all; export none; };\n"		\
  "  evpn { table evpntab; import all; export none; };\n"		\
  "}\n"									\
  "protocol bgp peer_e from fz { neighbor 192.0.2.2 as 65001; }\n"	\
  "protocol bgp peer_i from fz { neighbor 192.0.2.3 as 65000; rr client; }\n"

#define FUZZ_BGP_EBGP_AS	65001
#define FUZZ_BGP_IBGP_AS	65000

/* AFI/SAFI pairs advertised in the peer OPEN (MP, ADD-PATH, GR, LLGR). */
static const u16 fuzz_bgp_afs[][2] = {
  { BGP_AFI_IPV4, BGP_SAFI_UNICAST },
  { BGP_AFI_IPV6, BGP_SAFI_UNICAST },
  { BGP_AFI_IPV4, BGP_SAFI_MULTICAST },
  { BGP_AFI_IPV6, BGP_SAFI_MULTICAST },
  { BGP_AFI_IPV4, BGP_SAFI_MPLS },
  { BGP_AFI_IPV6, BGP_SAFI_MPLS },
  { BGP_AFI_IPV4, BGP_SAFI_MPLS_VPN },
  { BGP_AFI_IPV6, BGP_SAFI_MPLS_VPN },
  { BGP_AFI_IPV4, BGP_SAFI_VPN_MULTICAST },
  { BGP_AFI_IPV6, BGP_SAFI_VPN_MULTICAST },
  { BGP_AFI_IPV4, BGP_SAFI_FLOW },
  { BGP_AFI_IPV6, BGP_SAFI_FLOW },
  { BGP_AFI_L2VPN, BGP_SAFI_EVPN },
};
#define FUZZ_BGP_AF_COUNT (sizeof(fuzz_bgp_afs) / sizeof(fuzz_bgp_afs[0]))

/* ── Socket layer stubs ─────────────────────────────────────────────── */

int __real_sk_open(sock *s);
int __wrap_sk_open(sock *s);
int __wrap_sk_send(sock *s, uint len);

int
__wrap_sk_open(sock *s)
{
  if (!s->rbuf && s->rbsize)
    s->rbuf = s->rbuf_alloc = xmalloc(s->rbsize);
  s->rpos = s->rbuf;
  if (!s->tbuf && s->tbsize)
    s->tbuf = s->tbuf_alloc = xmalloc(s->tbsize);
  s->tpos = s->ttx = s->tbuf;
  s->fd = -1;
  return 0;
}

int
__wrap_sk_send(sock *s, uint len UNUSED)
{
  s->ttx = s->tpos = s->tbuf;
  return 1;
}

/* ── Session-preserving error paths ─────────────────────────────────── */

static uint fuzz_bgp_errors;

void __wrap_bgp_error(struct bgp_conn *c, uint code, uint subcode, byte *data, int len);
void __wrap_bgp_conn_enter_close_state(struct bgp_conn *conn);
void __wrap_bgp_conn_enter_idle_state(struct bgp_conn *conn);
void __wrap_bgp_stop(struct bgp_proto *p, int subcode, byte *data, uint len);

void
__wrap_bgp_error(struct bgp_conn *c, uint code, uint subcode, byte *data, int len)
{
  /* Keep the NOTIFICATION payload reachable, as bgp_create_notification
   * would read it. */
  c->notify_code = code;
  c->notify_subcode = subcode;
  c->notify_data = data;
  c->notify_size = (len > 0) ? len : 0;
  if (c->notify_size)
  {
    volatile byte sink = 0;
    for (uint i = 0; i < c->notify_size; i++)
      sink ^= data[i];
    (void) sink;
  }
  c->state = BS_CLOSE;
  fuzz_bgp_errors++;

  if (fuzz_verbose())
    fprintf(stderr, "fuzz: %s: bgp_error(%u, %u)\n", c->bgp->p.name, code, subcode);
}

void
__wrap_bgp_conn_enter_close_state(struct bgp_conn *conn)
{
  conn->state = BS_CLOSE;
}

void
__wrap_bgp_conn_enter_idle_state(struct bgp_conn *conn)
{
  conn->state = BS_CLOSE;
}

void
__wrap_bgp_stop(struct bgp_proto *p UNUSED, int subcode UNUSED, byte *data UNUSED, uint len UNUSED)
{
}

/* ── Message builders ───────────────────────────────────────────────── */

static uint
fuzz_bgp_header(byte *buf, uint len, uint type)
{
  memset(buf, 0xff, 16);
  put_u16(buf + 16, len);
  buf[18] = type;
  return len;
}

/* Peer OPEN: AS4, MP + ADD-PATH (both ways) + GR + LLGR for every AF,
 * route refresh, enhanced route refresh, extended next hop (IPv4 over
 * IPv6), extended messages and hostname, in RFC 9072 extended optional
 * parameters. Returns the message length. */
static uint
fuzz_bgp_build_open(byte *buf, u32 asn, u32 id)
{
  byte *pos = buf + BGP_HEADER_LENGTH;

  *pos++ = BGP_VERSION;
  put_u16(pos, (asn > 0xffff) ? AS_TRANS : asn); pos += 2;
  put_u16(pos, 240); pos += 2;
  put_u32(pos, id); pos += 4;

  /* All capabilities don't fit the classic one-byte option lengths, so
   * use the RFC 9072 extended form: non-extended length 255, marker 255,
   * two-byte total length, then options with two-byte lengths. */
  *pos++ = 255;
  *pos++ = 255;
  byte *optlen = pos; pos += 2;
  byte *opt = pos;
  *pos++ = 2;			/* Optional parameter: capabilities */
  byte *caplen = pos; pos += 2;
  byte *caps = pos;

  for (uint i = 0; i < FUZZ_BGP_AF_COUNT; i++)
  {
    *pos++ = 1; *pos++ = 4;	/* Multiprotocol */
    put_u16(pos, fuzz_bgp_afs[i][0]); pos += 2;
    *pos++ = 0;
    *pos++ = fuzz_bgp_afs[i][1];
  }

  *pos++ = 2; *pos++ = 0;	/* Route refresh */
  *pos++ = 70; *pos++ = 0;	/* Enhanced route refresh */
  *pos++ = 6; *pos++ = 0;	/* Extended messages */

  *pos++ = 5; *pos++ = 6;	/* Extended next hop: IPv4 unicast over IPv6 */
  put_u16(pos, BGP_AFI_IPV4); pos += 2;
  put_u16(pos, BGP_SAFI_UNICAST); pos += 2;
  put_u16(pos, BGP_AFI_IPV6); pos += 2;

  *pos++ = 64; *pos++ = 2 + 4 * FUZZ_BGP_AF_COUNT;	/* Graceful restart */
  put_u16(pos, 120); pos += 2;
  for (uint i = 0; i < FUZZ_BGP_AF_COUNT; i++)
  {
    put_u16(pos, fuzz_bgp_afs[i][0]); pos += 2;
    *pos++ = fuzz_bgp_afs[i][1];
    *pos++ = 0x80;		/* Forwarding state preserved */
  }

  *pos++ = 65; *pos++ = 4;	/* 4-octet AS */
  put_u32(pos, asn); pos += 4;

  *pos++ = 69; *pos++ = 4 * FUZZ_BGP_AF_COUNT;	/* ADD-PATH */
  for (uint i = 0; i < FUZZ_BGP_AF_COUNT; i++)
  {
    put_u16(pos, fuzz_bgp_afs[i][0]); pos += 2;
    *pos++ = fuzz_bgp_afs[i][1];
    *pos++ = BGP_ADD_PATH_FULL;
  }

  *pos++ = 71; *pos++ = 7 * FUZZ_BGP_AF_COUNT;	/* Long-lived GR */
  for (uint i = 0; i < FUZZ_BGP_AF_COUNT; i++)
  {
    put_u16(pos, fuzz_bgp_afs[i][0]); pos += 2;
    *pos++ = fuzz_bgp_afs[i][1];
    *pos++ = 0x80;
    put_u24(pos, 3600); pos += 3;
  }

  *pos++ = 73; *pos++ = 6;	/* Hostname "peer", no domain */
  *pos++ = 4; memcpy(pos, "peer", 4); pos += 4;
  *pos++ = 0;

  put_u16(caplen, pos - caps);
  put_u16(optlen, pos - opt);

  return fuzz_bgp_header(buf, pos - buf, PKT_OPEN);
}

/* Feed one buffer to the connection exactly as the socket layer would. */
static void
fuzz_bgp_feed(struct bgp_conn *conn, const byte *data, uint len)
{
  sock *sk = conn->sk;

  if (len > sk->rbsize)
    len = sk->rbsize;
  memcpy(sk->rbuf, data, len);
  sk->rpos = sk->rbuf + len;
  if (sk->rx_hook)
    sk->rx_hook(sk, len);
  sk->rpos = sk->rbuf;
}

/* ── Session bring-up ───────────────────────────────────────────────── */

static struct bgp_proto *
fuzz_bgp_find(const char *name)
{
  struct proto *p;

  WALK_LIST(p, proto_list)
    if ((p->proto == &proto_bgp) && !strcmp(p->name, name))
      return (struct bgp_proto *) p;

  fprintf(stderr, "fuzz: BGP protocol %s not found\n", name);
  abort();
}

/* Run the connect timer and the TCP-connected hook: OPEN sent, OpenSent. */
static struct bgp_conn *
fuzz_bgp_connect(struct bgp_proto *p)
{
  struct bgp_conn *conn = &p->outgoing_conn;

  fuzz_pump();
  if (conn->state != BS_ACTIVE)
  {
    fprintf(stderr, "fuzz: %s not in Active state (%u)\n", p->p.name, conn->state);
    abort();
  }

  conn->connect_timer->hook(conn->connect_timer);
  if ((conn->state != BS_CONNECT) || !conn->sk || !conn->sk->tx_hook)
  {
    fprintf(stderr, "fuzz: %s did not connect (%u)\n", p->p.name, conn->state);
    abort();
  }

  conn->sk->tx_hook(conn->sk);
  fuzz_pump();
  if (conn->state != BS_OPENSENT)
  {
    fprintf(stderr, "fuzz: %s not in OpenSent state (%u)\n", p->p.name, conn->state);
    abort();
  }

  return conn;
}

/* Peer OPEN + KEEPALIVE: Established, channels up. */
static void
fuzz_bgp_establish(struct bgp_proto *p, struct bgp_conn *conn, u32 asn, u32 id)
{
  byte buf[BGP_MAX_MESSAGE_LENGTH];

  fuzz_bgp_feed(conn, buf, fuzz_bgp_build_open(buf, asn, id));
  fuzz_pump();
  fuzz_bgp_feed(conn, buf, fuzz_bgp_header(buf, BGP_HEADER_LENGTH, PKT_KEEPALIVE));
  fuzz_pump();

  if ((conn->state != BS_ESTABLISHED) || (p->p.proto_state != PS_UP))
  {
    fprintf(stderr, "fuzz: %s not established (conn %u, proto %u, errors %u)\n",
	    p->p.name, conn->state, p->p.proto_state, fuzz_bgp_errors);
    abort();
  }

  if (p->channel_count != FUZZ_BGP_AF_COUNT)
  {
    fprintf(stderr, "fuzz: %s has %u active channels, expected %u\n",
	    p->p.name, p->channel_count, (uint) FUZZ_BGP_AF_COUNT);
    abort();
  }
}

#endif
