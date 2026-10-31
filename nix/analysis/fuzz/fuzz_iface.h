/*
 *	A fake network interface for the protocol harnesses.
 *
 *	The unit test environment has no interfaces: nothing runs the kernel
 *	interface scan. fuzz_iface_add() reports one the way the netlink
 *	code does for an async RTM_NEWLINK / RTM_NEWADDR (if_update(),
 *	ifa_update(), if_end_partial_update()), so interface-based protocols
 *	(OSPF, Babel, RIP, single-hop BFD) see it come up, create their
 *	per-interface state and open their sockets. Add interfaces after
 *	the config commit, so the protocols already exist to see them.
 *
 *	Interface code assumes the device protocol runs (kif_proto), so the
 *	harness config includes FUZZ_DEVICE_CONFIG, and fuzz.mk links with
 *	FUZZ_IFACE_WRAPS: kif_sys_start() (opens netlink sockets) and
 *	kif_do_scan() (imports the host's real interfaces) do nothing.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_NIX_FUZZ_IFACE_H_
#define _BIRD_NIX_FUZZ_IFACE_H_

#include "fuzz_bird.h"

#include "nest/iface.h"
#include "sysdep/unix/krt.h"

#define FUZZ_DEVICE_CONFIG	"protocol device { scan time 86400; }\n"

void __wrap_kif_sys_start(struct kif_proto *p);
void __wrap_kif_do_scan(struct kif_proto *p);

void __wrap_kif_sys_start(struct kif_proto *p UNUSED) { }
void __wrap_kif_do_scan(struct kif_proto *p UNUSED) { }

/* Interface n (0, 1, ...) is "fz<n>" with OS index n + 2 and these
 * addresses; host 1 is BIRD, host 2 the peer the harnesses impersonate. */
#define FUZZ_IP4(n, host)	ipa_build4(10, 0, (n), (host))
#define FUZZ_IP6(n, host)	ipa_build6(0x20010db8, (n), 0, (host))
#define FUZZ_LL6(host)		ipa_build6(0xfe800000, 0, 0, (host))

static void
fuzz_ifa_add(struct iface *i, ip_addr ip, uint pxlen)
{
  struct ifa a = {
    .iface = i,
    .ip = ip,
  };

  if (ipa_is_ip4(ip))
  {
    net_fill_ip4(&a.prefix, ipa_to_ip4(ip), pxlen);
    if (i->flags & IF_BROADCAST)
      a.brd = ipa_from_ip4(ip4_or(ipa_to_ip4(ip), ip4_not(ip4_mkmask(pxlen))));
  }
  else
    net_fill_ip6(&a.prefix, ipa_to_ip6(ip), pxlen);

  net_normalize(&a.prefix);
  a.scope = ipa_classify(ip) & IADDR_SCOPE_MASK;
  ifa_update(&a);
}

/* Interface n: broadcast, multicast-capable, Ethernet-like, up, with
 * 10.0.<n>.1/24, 2001:db8:0:<n>::1/64 and fe80::1/64. */
static struct iface *
fuzz_iface_add(uint n)
{
  struct iface f = {
    .flags = IF_ADMIN_UP | IF_LINK_UP | IF_MULTIACCESS | IF_BROADCAST | IF_MULTICAST,
    .mtu = 1500,
    .index = n + 2,
  };
  bsnprintf(f.name, sizeof(f.name), "fz%u", n);

  struct iface *i = if_update(&f);

  fuzz_ifa_add(i, FUZZ_IP4(n, 1), 24);
  fuzz_ifa_add(i, FUZZ_IP6(n, 1), 64);
  fuzz_ifa_add(i, FUZZ_LL6(1), 64);

  if_end_partial_update(i);
  fuzz_pump();

  if (!(i->flags & IF_UP) || !i->addr4 || !i->addr6 || !i->llv6)
  {
    fprintf(stderr, "fuzz: interface %s did not come up (flags 0x%x)\n", i->name, i->flags);
    abort();
  }

  return i;
}

#endif
