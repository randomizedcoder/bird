/*
 *	libFuzzer harness: RIPv2 and RIPng packets.
 *
 *	Reachable from any host on a RIP-enabled link (UDP 520 / 521):
 *	rip_rx_hook() checks (neighbour, TTL, port, version, the RFC 2091
 *	update header), rip_check_authentication() (plaintext and
 *	cryptographic: the auth block, the trailer, sequence numbers),
 *	rip_receive_request() / _response() / _ack(), the route block
 *	parsers (IPv4 incl. next hop, IPv6 incl. next-hop blocks), route
 *	import, and the replies and triggered updates (sent through the
 *	stubbed socket).
 *
 *	Five instances, each on its own fake interface (fuzz_iface.h):
 *	  0  r_plain   fz0  RIPv2, no authentication
 *	  1  r_crypto  fz1  RIPv2, cryptographic (HMAC-SHA256) authentication
 *	  2  r_text    fz2  RIPv2, plaintext password "fuzz"
 *	  3  r_demand  fz3  RIPv2, demand circuit (RFC 2091 update messages)
 *	  4  r_ng      fz4  RIPng
 *
 *	Input: one control byte, then the RIP packet (from the command byte).
 *	  bits 0-2  instance (values 5-7 wrap to 0-2)
 *	  bit 3     destination: 0 = the RIP multicast group, 1 = BIRD (unicast)
 *	  bit 4     source: 0 = host 2, 1 = host 3 on the link (two neighbours)
 *	  bit 5     a time byte follows: afterwards, advance the clock by it
 *	            (fuzz_advance_byte()) and run the timers that are due
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "fuzz_sock.h"
#include "fuzz_iface.h"

#include "proto/rip/rip.h"

#define FUZZ_RIP_COUNT	5

#define FUZZ_RIP_CONFIG							\
  "router id 10.0.0.1;\n"						\
  FUZZ_DEVICE_CONFIG							\
  "protocol rip r_plain {\n"						\
  "  ipv4 { import all; export all; };\n"				\
  "  interface \"fz0\" { version 2; };\n"				\
  "}\n"									\
  "protocol rip r_crypto {\n"						\
  "  ipv4 { import all; export all; };\n"				\
  "  interface \"fz1\" {\n"						\
  "    authentication cryptographic;\n"					\
  "    password \"fuzz\" { algorithm hmac sha256; };\n"			\
  "  };\n"								\
  "}\n"									\
  "protocol rip r_text {\n"						\
  "  ipv4 { import all; export all; };\n"				\
  "  interface \"fz2\" { authentication plaintext; password \"fuzz\"; };\n" \
  "}\n"									\
  "protocol rip r_demand {\n"						\
  "  ipv4 { import all; export all; };\n"				\
  "  interface \"fz3\" { demand circuit yes; };\n"			\
  "}\n"									\
  "protocol rip ng r_ng {\n"						\
  "  ipv6 { import all; export all; };\n"				\
  "  interface \"fz4\";\n"						\
  "}\n"

static const char *fuzz_names[FUZZ_RIP_COUNT] = {
  "r_plain", "r_crypto", "r_text", "r_demand", "r_ng",
};

static struct rip_proto *fuzz_p[FUZZ_RIP_COUNT];
static struct rip_iface *fuzz_ifa[FUZZ_RIP_COUNT];
static byte fuzz_buf[65536];

static struct rip_iface *
fuzz_rip_iface(struct rip_proto *p)
{
  struct rip_iface *ifa;

  WALK_LIST(ifa, p->iface_list)
    if (ifa->sk)
      return ifa;

  fprintf(stderr, "fuzz: %s has no interface with a socket\n", p->p.name);
  abort();
}

static void
fuzz_setup(void)
{
  fuzz_bird_init(FUZZ_RIP_CONFIG);

  for (int i = 0; i < FUZZ_RIP_COUNT; i++)
    fuzz_p[i] = (struct rip_proto *) fuzz_proto_find(&proto_rip, fuzz_names[i]);

  for (int i = 0; i < FUZZ_RIP_COUNT; i++)
    fuzz_iface_add(i);

  for (int i = 0; i < FUZZ_RIP_COUNT; i++)
    fuzz_ifa[i] = fuzz_rip_iface(fuzz_p[i]);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FUZZ_ONCE(fuzz_setup());

  uint8_t ctl = fuzz_take_byte(&data, &size);
  uint8_t dt = (ctl & 32) ? fuzz_take_byte(&data, &size) : 0;
  uint n = (ctl & 7) % FUZZ_RIP_COUNT;
  struct rip_proto *p = fuzz_p[n];
  struct rip_iface *ifa = fuzz_ifa[n];
  uint host = (ctl & 16) ? 3 : 2;

  if (size > sizeof(fuzz_buf))
    return 0;
  memcpy(fuzz_buf, data, size);

  struct fuzz_dgram d = {
    .fport = ifa->cf->port,
    .iface = ifa->iface,
    .ttl = 255,
  };

  if (p->rip2)
  {
    d.faddr = FUZZ_IP4(n, host);
    d.laddr = (ctl & 8) ? FUZZ_IP4(n, 1) : IP4_RIP_ROUTERS;
  }
  else
  {
    d.faddr = FUZZ_LL6(host);
    d.laddr = (ctl & 8) ? FUZZ_LL6(1) : IP6_RIP_ROUTERS;
  }

  fuzz_sk_feed(ifa->sk, fuzz_buf, size, &d);
  fuzz_pump();

  if (ctl & 32)
    fuzz_advance_byte(dt);

  return 0;
}
