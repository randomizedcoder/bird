/*
 *	libFuzzer harness: Linux netlink messages from the kernel.
 *
 *	Reachable from the kernel, i.e. from any local process that can
 *	change interfaces, addresses or routes (including ones with only
 *	CAP_NET_ADMIN in a network namespace BIRD runs in, and kernel
 *	features BIRD doesn't know): the async notification path
 *	(nl_async_msg(): RTM_NEW/DELLINK with IFLA_LINKINFO / VXLAN data,
 *	RTM_NEW/DELADDR for IPv4 and IPv6, RTM_NEW/DELROUTE, RTM_NEW/DELNEIGH
 *	bridge FDB entries) and the route table scan (nl_parse_route() with
 *	scan = 1, then krt_prune()): nl_parse_attrs(), multipath next hops,
 *	metrics, MPLS encapsulation and labels, and the import into the
 *	kernel protocols' tables (krt_got_route(), learn).
 *
 *	All of netlink.c is static, so this file #includes it; fuzz.mk
 *	leaves netlink.o out of this harness's link. No netlink socket is
 *	opened: krt_sys_start() only registers the table (-Wl,--wrap), the
 *	device protocol's start and scan do nothing (fuzz_iface.h), and
 *	krt_do_scan() parses the fuzz input instead of a kernel dump. The
 *	requests BIRD sends back (e.g. deleting a stale route of its own)
 *	go to fuzz_nl_sendto(), and fuzz_nl_recvmsg() acknowledges each one,
 *	as the kernel would; the real calls die() on the closed socket.
 *
 *	Input: one control byte, then a stream of netlink messages (struct
 *	nlmsghdr framing, NLMSG_ALIGN padding, as recvmsg() returns them;
 *	trailing bytes past a multiple of 4 are dropped).
 *	  bit 0  0 = async notifications (nl_async_msg)
 *	         1 = route table scan (krt_scan timer of a kernel protocol)
 *	  bits 1-2  scanning protocol: 0 = k4 (main), 1 = k6 (main),
 *	            2 = k4t (table 100), 3 = kmpls
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <sys/socket.h>
#include <sys/uio.h>
#include <linux/netlink.h>

/* netlink.c's own socket calls, see above */
static ssize_t fuzz_nl_sendto(int fd, const void *buf, size_t len, int flags,
			      const struct sockaddr *sa, socklen_t salen);
static ssize_t fuzz_nl_recvmsg(int fd, struct msghdr *m, int flags);

#define sendto(fd, buf, len, flags, sa, salen) \
  fuzz_nl_sendto(fd, buf, len, flags, (const struct sockaddr *) (sa), salen)
#define recvmsg fuzz_nl_recvmsg

#include "sysdep/linux/netlink.c"

#undef sendto
#undef recvmsg

#include "fuzz_iface.h"

#define FUZZ_NETLINK_CONFIG						\
  "router id 10.0.0.1;\n"						\
  FUZZ_DEVICE_CONFIG							\
  "ipv4 table t2;\n"							\
  "mpls domain mdom;\n"							\
  "mpls table mtab;\n"							\
  "protocol kernel k4 {\n"						\
  "  ipv4 { import all; export all; };\n"				\
  "  learn all; merge paths yes; scan time 86400;\n"			\
  "}\n"									\
  "protocol kernel k6 {\n"						\
  "  ipv6 { import all; export all; };\n"				\
  "  learn all; merge paths yes; scan time 86400;\n"			\
  "}\n"									\
  "protocol kernel k4t {\n"						\
  "  ipv4 { table t2; import all; export all; };\n"			\
  "  kernel table 100; learn; scan time 86400;\n"			\
  "}\n"									\
  "protocol kernel kmpls {\n"						\
  "  mpls { table mtab; import all; export all; };\n"			\
  "  learn all; scan time 86400;\n"					\
  "}\n"

static const char *fuzz_krt_names[4] = { "k4", "k6", "k4t", "kmpls" };
static struct krt_proto *fuzz_krt[4];

/* The input, copied to an exactly-sized heap buffer (malloc alignment, as
 * the kernel's recvmsg() buffer has), so ASan sees reads past it */
static byte *fuzz_msg;
static uint fuzz_scan_len;

static struct nlmsghdr fuzz_nl_last;	/* Header of the last request */

static ssize_t
fuzz_nl_sendto(int fd UNUSED, const void *buf, size_t len, int flags UNUSED,
	       const struct sockaddr *sa UNUSED, socklen_t salen UNUSED)
{
  memcpy(&fuzz_nl_last, buf, sizeof(fuzz_nl_last));
  return len;
}

/* An NLMSG_ERROR with error 0 (ACK) for the last request. */
static ssize_t
fuzz_nl_recvmsg(int fd UNUSED, struct msghdr *m, int flags UNUSED)
{
  struct {
    struct nlmsghdr h;
    struct nlmsgerr e;
  } ack = {
    .h = {
      .nlmsg_len = sizeof(ack),
      .nlmsg_type = NLMSG_ERROR,
      .nlmsg_seq = fuzz_nl_last.nlmsg_seq,
    },
    .e = { .error = 0, .msg = fuzz_nl_last },
  };

  if (m->msg_name)
    memset(m->msg_name, 0, m->msg_namelen);
  m->msg_flags = 0;

  size_t len = MIN(sizeof(ack), m->msg_iov[0].iov_len);
  memcpy(m->msg_iov[0].iov_base, &ack, len);
  return len;
}

int __wrap_krt_sys_start(struct krt_proto *p);
void __wrap_krt_do_scan(struct krt_proto *p);
static int fuzz_nl_known_bug(struct nlmsghdr *h);

/* Only register the table, as the real one does before opening the
 * netlink sockets. */
int
__wrap_krt_sys_start(struct krt_proto *p)
{
  if (HASH_FIND(nl_table_map, RTH, p->af, krt_table_id(p)))
    return 0;

  HASH_INSERT2(nl_table_map, RTH, krt_pool, p);
  return 1;
}

/* A route table dump, with the fuzz input as the kernel's reply. */
void
__wrap_krt_do_scan(struct krt_proto *p)
{
  struct nl_parse_state s = {
    .proto = p,
    .pool = nl_linpool,
    .scan = 1,
  };

  struct nlmsghdr *h = (void *) fuzz_msg;
  uint len = fuzz_scan_len;
  fuzz_scan_len = 0;

  for (; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len))
    if (((h->nlmsg_type == RTM_NEWROUTE) || (h->nlmsg_type == RTM_DELROUTE)) &&
	!fuzz_nl_known_bug(h))
      nl_parse_route(&s, h);
}

/* Known findings, skipped so they do not stop every run. Both need the
 * kernel to send a malformed message (nl_async_hook() drops anything not
 * from the kernel), so they are robustness bugs. Remove each check once
 * the parser is fixed.
 *
 * 1. nl_parse_addr4() / nl_parse_addr6() log "Invalid prefix length" for
 *    ifa_prefixlen > 32 / 128 but carry on with it (only turning the add
 *    into a delete): net_normalize() -> u32_mkmask(33) shifts by -1
 *    (UBSan shift-exponent, lib/bitops.c:22).
 * 2. nl_parse_multipath() checks only len < sizeof(*nh) || len < rtnh_len
 *    (its own comment asks "Use RTNH_OK(nh,len) ??"), then advances by
 *    NLMSG_ALIGN(rtnh_len):
 *    a. rtnh_len == 0 on a skipped (RTNH_F_DEAD) next hop: `len -= 0`,
 *       infinite loop;
 *    b. unaligned rtnh_len in an unaligned RTA_MULTIPATH payload: the
 *       unsigned len wraps and the next iteration reads past the message
 *       (ASan heap-buffer-overflow, netlink.c:900). */
static int
fuzz_nl_known_bug(struct nlmsghdr *h)
{
  if (((h->nlmsg_type == RTM_NEWADDR) || (h->nlmsg_type == RTM_DELADDR)) &&
      (h->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifaddrmsg))))
  {
    struct ifaddrmsg *i = NLMSG_DATA(h);
    return ((i->ifa_family == AF_INET) && (i->ifa_prefixlen > IP4_MAX_PREFIX_LENGTH)) ||
	   ((i->ifa_family == AF_INET6) && (i->ifa_prefixlen > IP6_MAX_PREFIX_LENGTH));
  }

  if (((h->nlmsg_type == RTM_NEWROUTE) || (h->nlmsg_type == RTM_DELROUTE)) &&
      (h->nlmsg_len >= NLMSG_LENGTH(sizeof(struct rtmsg))))
  {
    struct rtattr *a = RTM_RTA(NLMSG_DATA(h));
    int alen = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));

    for (; RTA_OK(a, alen); a = RTA_NEXT(a, alen))
    {
      if (a->rta_type != RTA_MULTIPATH)
	continue;

      struct rtnexthop *nh = RTA_DATA(a);
      uint len = RTA_PAYLOAD(a);

      while ((len >= sizeof(*nh)) && (len >= nh->rtnh_len))
      {
	if (!nh->rtnh_len || (NLMSG_ALIGN(nh->rtnh_len) > len))
	  return 1;
	len -= NLMSG_ALIGN(nh->rtnh_len);
	nh = RTNH_NEXT(nh);
      }
    }
  }

  return 0;
}

static void
fuzz_setup(void)
{
  /* nl_open() would allocate these with the sockets */
  nl_scan.rx_buffer = xmalloc(NL_RX_SIZE);
  nl_req.rx_buffer = xmalloc(NL_RX_SIZE);

  fuzz_bird_init(FUZZ_NETLINK_CONFIG);

  for (int i = 0; i < 4; i++)
    fuzz_krt[i] = (struct krt_proto *) fuzz_proto_find(&proto_unix_kernel, fuzz_krt_names[i]);

  fuzz_iface_add(0);

  for (int i = 0; i < 4; i++)
    if (!fuzz_krt[i]->scan_timer)
    {
      fprintf(stderr, "fuzz: %s has no scan timer\n", fuzz_krt_names[i]);
      abort();
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FUZZ_ONCE(fuzz_setup());

  uint8_t ctl = fuzz_take_byte(&data, &size);

  /* The kernel pads every message to NLMSG_ALIGNTO, so what recvmsg()
   * returns is a multiple of 4; BIRD's NLMSG_NEXT() loops (with an
   * unsigned length, like these) rely on that, and nl_async_hook() drops
   * messages not sent by the kernel. */
  size &= ~(size_t) (NLMSG_ALIGNTO - 1);

  if (size > 65536)
    return 0;

  fuzz_msg = xmalloc(size ?: 1);
  memcpy(fuzz_msg, data, size);

  if (ctl & 1)
  {
    struct krt_proto *p = fuzz_krt[(ctl >> 1) & 3];

    fuzz_scan_len = size;
    p->scan_timer->hook(p->scan_timer);	/* krt_scan(): init, do_scan, prune */
  }
  else
  {
    struct nlmsghdr *h = (void *) fuzz_msg;
    uint len = size;

    for (; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len))
      if (!fuzz_nl_known_bug(h))
	nl_async_msg(h);
  }

  fuzz_pump();
  xfree(fuzz_msg);
  fuzz_msg = NULL;
  return 0;
}
