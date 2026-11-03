/*
 *	libFuzzer harness: BFD control packets.
 *
 *	Reachable from any host that can send UDP to BIRD's BFD ports (3784
 *	single-hop with TTL 255, 4784 multihop): bfd_rx_hook() (version,
 *	length, detect multiplier, flags, discriminators, session lookup by
 *	discriminator or by address), bfd_check_authentication() (simple
 *	password, keyed / meticulous keyed MD5 and SHA1: auth section
 *	parsing, key lookup, sequence numbers, digest check), then
 *	bfd_session_process_ctl(): the session state machine, poll / final
 *	handling and interval negotiation.
 *
 *	BFD normally runs in its own thread (proto/bfd/io.c birdloop). Here
 *	birdloop_start() is wrapped to do nothing, so no thread starts; the
 *	harness calls the rx hook itself, holding the loop as the thread would
 *	(birdloop_enter() / birdloop_leave()). BFD timers belong to that loop,
 *	so they don't run; the state notifications to the main thread queue.
 *
 *	Three sessions from the config (fuzz_iface.h interfaces):
 *	  0  10.0.0.2 on fz0, single-hop, keyed MD5 (password "fuzz")
 *	  1  10.9.0.2, multihop from 10.0.0.1, no authentication
 *	  2  2001:db8:0:1::2 on fz1, single-hop, meticulous keyed SHA1
 *
 *	Input: one control byte, then the BFD control packet.
 *	  bits 0-1  session (3 = 0)
 *	  bit 2     set Your Discriminator to the session's local
 *	            discriminator (else as given; 0 = lookup by address)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "fuzz_sock.h"
#include "fuzz_iface.h"

#include "proto/bfd/bfd.h"
#include "proto/bfd/io.h"

#define FUZZ_BFD_CONFIG							\
  "router id 10.0.0.1;\n"						\
  FUZZ_DEVICE_CONFIG							\
  "protocol bfd bf {\n"							\
  "  interface \"fz0\" { authentication keyed md5; password \"fuzz\"; };\n" \
  "  interface \"fz1\" { authentication meticulous keyed sha1; password \"fuzz\"; };\n" \
  "  neighbor 10.0.0.2 dev \"fz0\";\n"					\
  "  neighbor 10.9.0.2 local 10.0.0.1 multihop yes;\n"			\
  "  neighbor 2001:db8:0:1::2 dev \"fz1\";\n"				\
  "}\n"

static struct bfd_proto *fuzz_p;
static struct bfd_session *fuzz_s[3];
static sock *fuzz_sk[3];
static struct iface *fuzz_if[2];
static ip_addr fuzz_addr[3];

void __wrap_birdloop_start(struct birdloop *loop);
void __wrap_birdloop_start(struct birdloop *loop UNUSED) { }

static void
fuzz_setup(void)
{
  fuzz_bird_init(FUZZ_BFD_CONFIG);
  fuzz_p = (struct bfd_proto *) fuzz_proto_find(&proto_bfd, "bf");

  fuzz_if[0] = fuzz_iface_add(0);
  fuzz_if[1] = fuzz_iface_add(1);

  fuzz_addr[0] = FUZZ_IP4(0, 2);
  fuzz_addr[1] = ipa_build4(10, 9, 0, 2);
  fuzz_addr[2] = FUZZ_IP6(1, 2);

  uint ifindex[3] = { fuzz_if[0]->index, 0, fuzz_if[1]->index };
  fuzz_sk[0] = fuzz_p->rx4_1;
  fuzz_sk[1] = fuzz_p->rx4_m;
  fuzz_sk[2] = fuzz_p->rx6_1;

  birdloop_enter(fuzz_p->loop);
  for (uint i = 0; i < 3; i++)
    fuzz_s[i] = bfd_find_session_by_addr(fuzz_p, fuzz_addr[i], ifindex[i]);
  birdloop_leave(fuzz_p->loop);

  for (uint i = 0; i < 3; i++)
    if (!fuzz_s[i] || !fuzz_sk[i])
    {
      fprintf(stderr, "fuzz: BFD session %u missing (session %p, socket %p)\n",
	      i, fuzz_s[i], fuzz_sk[i]);
      abort();
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FUZZ_ONCE(fuzz_setup());

  uint8_t ctl = fuzz_take_byte(&data, &size);
  uint i = (ctl & 3) % 3;
  sock *sk = fuzz_sk[i];

  if (size > sk->rbsize)
    return 0;

  byte buf[size ?: 1];
  memcpy(buf, data, size);

  /* Your Discriminator at offset 8 */
  if ((ctl & 4) && (size >= 12))
    put_u32(buf + 8, fuzz_s[i]->loc_id);

  struct fuzz_dgram d = {
    .faddr = fuzz_addr[i],
    .laddr = (i == 2) ? FUZZ_IP6(1, 1) : FUZZ_IP4(0, 1),
    .fport = 49152,
    .iface = (i == 1) ? NULL : fuzz_if[i / 2],
    .ttl = 255,
  };

  birdloop_enter(fuzz_p->loop);
  fuzz_sk_feed(sk, buf, size, &d);
  birdloop_leave(fuzz_p->loop);
  fuzz_pump();

  return 0;
}
