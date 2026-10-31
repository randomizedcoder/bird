/*
 *	libFuzzer harness: Babel packets.
 *
 *	Reachable from any host on a Babel-enabled link (UDP 6696, link-local
 *	source): babel_rx_hook(), babel_process_packet(), the TLV and sub-TLV
 *	parsers (babel_read_tlv() and the per-TLV readers: Hello, IHU, Router
 *	ID, Next Hop, Update incl. prefix compression and source-specific
 *	prefixes, Route/Seqno Request, Ack Request), the MAC/PC/challenge
 *	trailer (babel_auth_check()), then the TLV handlers: neighbour and
 *	cost tracking, RTT timestamps, route selection and the triggered
 *	updates and replies (sent through the stubbed socket).
 *
 *	Two instances, each on its own fake interface (fuzz_iface.h):
 *	  b_plain  fz0, wired, no authentication, RTT cost from timestamps,
 *	           IPv4 + IPv6 channels
 *	  b_auth   fz1, wireless, MAC authentication in permissive mode (MAC
 *	           and PC TLVs are parsed and checked, but failing packets are
 *	           still processed), IPv4 + IPv6 SADR channels
 *
 *	Input: one control byte, then the packet.
 *	  bit 0  instance: 0 = b_plain, 1 = b_auth
 *	  bit 1  destination: 0 = ff02::1:6 (multicast), 1 = fe80::1 (unicast)
 *	  bit 2  source: 0 = fe80::2, 1 = fe80::3 (two neighbours)
 *	  bit 3  0 = TLVs only, the harness adds the 4-byte header with the
 *	           right length; 1 = raw packet incl. header (and trailer)
 *	  bit 4  a time byte follows: afterwards, advance the clock by it
 *	         (fuzz_advance_byte()) and run the timers that are due
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "fuzz_sock.h"
#include "fuzz_iface.h"

#include "proto/babel/babel.h"

#define FUZZ_BABEL_CONFIG						\
  "router id 10.0.0.1;\n"						\
  FUZZ_DEVICE_CONFIG							\
  "ipv6 sadr table sadr6;\n"						\
  "protocol babel b_plain {\n"						\
  "  ipv4 { import all; export all; };\n"				\
  "  ipv6 { import all; export all; };\n"				\
  "  interface \"fz0\" { type wired; rtt cost 96; send timestamps yes; };\n" \
  "}\n"									\
  "protocol babel b_auth {\n"						\
  "  ipv4 { import all; export all; };\n"				\
  "  ipv6 sadr { table sadr6; import all; export all; };\n"		\
  "  interface \"fz1\" {\n"						\
  "    type wireless;\n"						\
  "    authentication mac permissive;\n"				\
  "    password \"fuzz\" { algorithm hmac sha256; };\n"			\
  "  };\n"								\
  "}\n"

static struct babel_proto *fuzz_p[2];
static struct babel_iface *fuzz_ifa[2];
static byte fuzz_buf[65536];

static struct babel_iface *
fuzz_babel_iface(struct babel_proto *p)
{
  struct babel_iface *ifa;

  WALK_LIST(ifa, p->interfaces)
    if (ifa->sk)
      return ifa;

  fprintf(stderr, "fuzz: %s has no interface with a socket\n", p->p.name);
  abort();
}

static void
fuzz_setup(void)
{
  fuzz_bird_init(FUZZ_BABEL_CONFIG);

  fuzz_p[0] = (struct babel_proto *) fuzz_proto_find(&proto_babel, "b_plain");
  fuzz_p[1] = (struct babel_proto *) fuzz_proto_find(&proto_babel, "b_auth");

  fuzz_iface_add(0);
  fuzz_iface_add(1);

  for (int i = 0; i < 2; i++)
    fuzz_ifa[i] = fuzz_babel_iface(fuzz_p[i]);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FUZZ_ONCE(fuzz_setup());

  uint8_t ctl = fuzz_take_byte(&data, &size);
  uint8_t dt = (ctl & 16) ? fuzz_take_byte(&data, &size) : 0;
  struct babel_iface *ifa = fuzz_ifa[ctl & 1];
  uint len;

  if (ctl & 8)
  {
    if (size > sizeof(fuzz_buf))
      return 0;
    memcpy(fuzz_buf, data, size);
    len = size;
  }
  else
  {
    if (size > sizeof(fuzz_buf) - 4)
      return 0;
    fuzz_buf[0] = BABEL_MAGIC;
    fuzz_buf[1] = BABEL_VERSION;
    put_u16(fuzz_buf + 2, size);
    memcpy(fuzz_buf + 4, data, size);
    len = size + 4;
  }

  struct fuzz_dgram d = {
    .faddr = FUZZ_LL6((ctl & 4) ? 3 : 2),
    .laddr = (ctl & 2) ? FUZZ_LL6(1) : IP6_BABEL_ROUTERS,
    .fport = BABEL_PORT,
    .iface = ifa->iface,
    .ttl = 1,
  };

  fuzz_sk_feed(ifa->sk, fuzz_buf, len, &d);
  fuzz_pump();

  if (ctl & 16)
    fuzz_advance_byte(dt);

  return 0;
}
