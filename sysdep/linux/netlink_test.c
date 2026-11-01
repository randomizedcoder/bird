/*
 *	BIRD -- Linux Netlink Parser Tests
 *
 *	(c) 2026 David Seddon <dave.seddon.ca@gmail.com>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/*
 * The parsers are static, so this file includes netlink.c (and the test
 * is linked without netlink.o, see Makefile). Their input comes from
 * captures of real kernel replies in sysdep/linux/test/, see README there;
 * each case takes one captured message, optionally changes one field or
 * attribute, and checks what the parser made of it.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "sysdep/linux/netlink.c"

#define NL_TEST_DIR "sysdep/linux/test/"

/*
 *	Captures
 */

#define NL_TEST_MAX_MSGS 64

struct nl_test_capture {
  uint count;
  struct nlmsghdr *msg[NL_TEST_MAX_MSGS];
};

struct pcap_file_header {
  u32 magic;
  u16 version_major, version_minor;
  s32 thiszone;
  u32 sigfigs, snaplen, linktype;
};

struct pcap_packet_header {
  u32 ts_sec, ts_usec, incl_len, orig_len;
};

#define PCAP_MAGIC		0xa1b2c3d4
#define LINKTYPE_NETLINK	253
#define NLMON_HEADER_LEN	16

/*
 * Read the messages the kernel sent from a pcap file captured on an nlmon
 * interface: each packet is a 16 byte pseudo header followed by the
 * datagram as the socket received it. Requests (NLM_F_REQUEST) are
 * skipped. Each message gets its own exactly sized buffer, so that reads
 * past it are caught by ASan.
 */
static void
nl_test_load(struct nl_test_capture *c, const char *name)
{
  char path[256];
  bsnprintf(path, sizeof(path), NL_TEST_DIR "%s", name);

  FILE *f = fopen(path, "rb");
  bt_syscall(!f, "fopen(%s)", path);

  struct pcap_file_header fh;
  if (fread(&fh, sizeof(fh), 1, f) != 1)
    bt_abort_msg("%s: short file header", path);
  if (fh.magic != PCAP_MAGIC)
    bt_abort_msg("%s: not a pcap file in host byte order", path);
  if (fh.linktype != LINKTYPE_NETLINK)
    bt_abort_msg("%s: link type %u is not netlink", path, fh.linktype);

  c->count = 0;

  struct pcap_packet_header ph;
  while (fread(&ph, sizeof(ph), 1, f) == 1)
  {
    byte *pkt = xmalloc(ph.incl_len);
    if (fread(pkt, ph.incl_len, 1, f) != 1)
      bt_abort_msg("%s: short packet", path);

    if (ph.incl_len >= NLMON_HEADER_LEN)
    {
      struct nlmsghdr *h = (void *) (pkt + NLMON_HEADER_LEN);
      uint len = ph.incl_len - NLMON_HEADER_LEN;

      for (; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len))
      {
	if (h->nlmsg_flags & NLM_F_REQUEST)
	  continue;

	if (c->count >= NL_TEST_MAX_MSGS)
	  bt_abort_msg("%s: more than %u messages", path, NL_TEST_MAX_MSGS);

	c->msg[c->count] = xmalloc(h->nlmsg_len);
	memcpy(c->msg[c->count], h, h->nlmsg_len);
	c->count++;
      }
    }

    xfree(pkt);
  }

  fclose(f);
  bt_debug("%s: %u kernel messages\n", path, c->count);
}

static void
nl_test_free(struct nl_test_capture *c)
{
  for (uint i = 0; i < c->count; i++)
    xfree(c->msg[i]);

  c->count = 0;
}

/* Attributes of message h, whose fixed header (after struct nlmsghdr) is hlen bytes */
static inline struct rtattr *
nl_test_attrs(struct nlmsghdr *h, uint hlen, int *len)
{
  *len = h->nlmsg_len - NLMSG_LENGTH(hlen);
  return (struct rtattr *) ((byte *) NLMSG_DATA(h) + NLMSG_ALIGN(hlen));
}

static struct rtattr *
nl_test_find_attr(struct nlmsghdr *h, uint hlen, uint type)
{
  int len;
  for (struct rtattr *a = nl_test_attrs(h, hlen, &len); RTA_OK(a, len); a = RTA_NEXT(a, len))
    if (a->rta_type == type)
      return a;

  return NULL;
}

/* An attribute change: replace attribute `type` with `len` bytes of data,
 * remove it (NL_TEST_DROP), or leave the message alone (type 0) */
#define NL_TEST_DROP	-1

struct nl_test_attr {
  u16 type;
  int len;
  const void *data;
};

/* A copy of h with attribute change m applied (appended if h has no such
 * attribute), in an exactly sized buffer */
static struct nlmsghdr *
nl_test_copy(struct nlmsghdr *h, uint hlen, const struct nl_test_attr *m)
{
  uint size = h->nlmsg_len + (m->len > 0 ? RTA_SPACE(m->len) : 0);
  struct nlmsghdr *n = xmalloc(size);
  int found = 0;

  memcpy(n, h, NLMSG_LENGTH(hlen));
  n->nlmsg_len = NLMSG_LENGTH(hlen);

  int len;
  for (struct rtattr *a = nl_test_attrs(h, hlen, &len); RTA_OK(a, len); a = RTA_NEXT(a, len))
  {
    const void *data = RTA_DATA(a);
    int dlen = RTA_PAYLOAD(a);

    if (m->type && (a->rta_type == m->type))
    {
      found = 1;
      if (m->len == NL_TEST_DROP)
	continue;

      data = m->data;
      dlen = m->len;
    }

    nl_add_attr(n, size, a->rta_type, data, dlen);
  }

  if (m->type && !found && (m->len >= 0))
    nl_add_attr(n, size, m->type, m->data, m->len);

  return n;
}


/*
 *	Links
 */

static const char *
nl_test_link_name(struct nlmsghdr *h)
{
  struct rtattr *a = nl_test_find_attr(h, sizeof(struct ifinfomsg), IFLA_IFNAME);
  return a ? RTA_DATA(a) : "";
}

static struct nlmsghdr *
nl_test_find_link(struct nl_test_capture *c, const char *name)
{
  for (uint i = 0; i < c->count; i++)
    if ((c->msg[i]->nlmsg_type == RTM_NEWLINK) && !strcmp(nl_test_link_name(c->msg[i]), name))
      return c->msg[i];

  bt_abort_msg("No link %s in the capture", name);
  return NULL;
}

/* One line describing interface i, for comparing with a case's expected text */
static void
nl_test_format_iface(struct iface *i, char *buf, uint size)
{
  static const struct { uint flag; const char *name; } flags[] = {
    { IF_ADMIN_UP, "admin-up" },
    { IF_LINK_UP, "link-up" },
    { IF_MULTIACCESS, "multiaccess" },
    { IF_BROADCAST, "broadcast" },
    { IF_MULTICAST, "multicast" },
    { IF_LOOPBACK, "loopback" },
    { IF_IGNORE, "ignore" },
    { IF_VRF, "vrf" },
    { IF_SHUTDOWN, "shutdown" },
  };

  if (!i)
  {
    bsnprintf(buf, size, "none");
    return;
  }

  char *pos = buf;
  pos += bsnprintf(pos, buf + size - pos, "%s index %u mtu %u", i->name, i->index, i->mtu);

  for (uint j = 0; j < ARRAY_SIZE(flags); j++)
    if (i->flags & flags[j].flag)
      pos += bsnprintf(pos, buf + size - pos, " %s", flags[j].name);

  if (i->master)
    pos += bsnprintf(pos, buf + size - pos, " master %s", i->master->name);

  const byte *m = i->lladdr.addr;
  if (m[0] | m[1] | m[2] | m[3] | m[4] | m[5])
  {
    bsnprintf(pos, buf + size - pos, " lladdr %02x:%02x:%02x:%02x:%02x:%02x",
	      m[0], m[1], m[2], m[3], m[4], m[5]);
  }
}

static int
nl_test_check_iface(const char *description, struct iface *i, const char *expected)
{
  char got[256];
  nl_test_format_iface(i, got, sizeof(got));
  bt_assert_msg(!strcmp(got, expected), "%s: got \"%s\", expected \"%s\"", description, got, expected);
  return 1;
}

static void
nl_test_load_links(struct nl_test_capture *c)
{
  nl_test_load(c, "link-dump.pcap");

  for (uint i = 0; i < c->count; i++)
    if (c->msg[i]->nlmsg_type == RTM_NEWLINK)
      nl_parse_link(c->msg[i], 0);
}

/* The links of the capture, as `ip -d link show` printed them:
 *
 *   1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
 *   2: nlmon0: <NOARP,UP,LOWER_UP> mtu 3776      link/netlink
 *   3: goip0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500   link/ether 5e:9c:8f:0b:ce:ae, dummy
 *   4: goipvrf: <NOARP,MASTER,UP,LOWER_UP> mtu 65575   vrf table 100
 *   5: goipv: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 master goipvrf
 */
static int
t_parse_link_capture(void)
{
  static const struct {
    const char *description;
    uint index;
    const char *expected;
  } cases[] = {
    { "loopback is ignored by protocols", 1,
      "lo index 1 mtu 65536 admin-up link-up multiaccess loopback ignore" },
    { "non-Ethernet link has no MAC address and is NBMA", 2,
      "nlmon0 index 2 mtu 3776 admin-up link-up multiaccess" },
    { "Ethernet dummy keeps its MAC address", 3,
      "goip0 index 3 mtu 1500 admin-up link-up multiaccess broadcast multicast lladdr 5e:9c:8f:0b:ce:ae" },
    { "VRF device is marked as VRF", 4,
      "goipvrf index 4 mtu 65575 admin-up link-up multiaccess vrf lladdr 4a:53:32:ed:29:e2" },
    { "VRF member has its master", 5,
      "goipv index 5 mtu 1500 admin-up link-up multiaccess broadcast multicast master goipvrf lladdr 86:da:71:5c:b3:da" },
    { "index not in the capture", 6, "none" },
    { "index 0 is never an interface", 0, "none" },
  };

  struct nl_test_capture c;
  nl_test_load_links(&c);

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
    nl_test_check_iface(cases[i].description, if_find_by_index(cases[i].index), cases[i].expected);

  nl_test_free(&c);

  return 1;
}

static const char nl_test_name1[] = "x";
static const char nl_test_name15[] = "abcdefghijklmno";
static const char nl_test_name16[] = "abcdefghijklmnop";
static const u32 nl_test_mtu0 = 0;
static const u32 nl_test_mtu_max = 0xffffffff;
static const byte nl_test_mac5[5] = { 2, 0, 0, 0, 0 };
static const byte nl_test_mac7[7] = { 2, 0, 0, 0, 0, 0, 7 };
static const u32 nl_test_master_missing = 99;
static const byte nl_test_kind_vrf[] = {
  /* IFLA_INFO_KIND "vrf" */
  8, 0, IFLA_INFO_KIND, 0, 'v', 'r', 'f', 0,
};

/* Changed copies of goip0's message, each under a new index */
static int
t_parse_link_changed(void)
{
  static const struct {
    const char *description;
    struct nl_test_attr attr;
    uint msg_len;		/* Truncate the message to this length, 0 keeps it */
    const char *expected;	/* "%u" stands for the case's index */
  } cases[] = {
    { "unchanged copy (positive)", {},
      0, "goip0 index %u mtu 1500 admin-up link-up multiaccess broadcast multicast lladdr 5e:9c:8f:0b:ce:ae" },
    { "one character name (boundary)", { IFLA_IFNAME, sizeof(nl_test_name1), nl_test_name1 },
      0, "x index %u mtu 1500 admin-up link-up multiaccess broadcast multicast lladdr 5e:9c:8f:0b:ce:ae" },
    { "15 character name, the longest that fits (boundary)", { IFLA_IFNAME, sizeof(nl_test_name15), nl_test_name15 },
      0, "abcdefghijklmno index %u mtu 1500 admin-up link-up multiaccess broadcast multicast lladdr 5e:9c:8f:0b:ce:ae" },
    { "16 character name is truncated (corner)", { IFLA_IFNAME, sizeof(nl_test_name16), nl_test_name16 },
      0, "abcdefghijklmno index %u mtu 1500 admin-up link-up multiaccess broadcast multicast lladdr 5e:9c:8f:0b:ce:ae" },
    { "empty name is rejected (negative)", { IFLA_IFNAME, 1, "" },
      0, "none" },
    { "no name is rejected (negative)", { IFLA_IFNAME, NL_TEST_DROP },
      0, "none" },
    { "no MTU is rejected (negative)", { IFLA_MTU, NL_TEST_DROP },
      0, "none" },
    { "MTU 0 (boundary)", { IFLA_MTU, sizeof(u32), &nl_test_mtu0 },
      0, "goip0 index %u mtu 0 admin-up link-up multiaccess broadcast multicast lladdr 5e:9c:8f:0b:ce:ae" },
    { "MTU 2^32-1 (boundary)", { IFLA_MTU, sizeof(u32), &nl_test_mtu_max },
      0, "goip0 index %u mtu 4294967295 admin-up link-up multiaccess broadcast multicast lladdr 5e:9c:8f:0b:ce:ae" },
    { "5 byte MAC address is ignored (corner)", { IFLA_ADDRESS, sizeof(nl_test_mac5), nl_test_mac5 },
      0, "goip0 index %u mtu 1500 admin-up link-up multiaccess broadcast multicast" },
    { "7 byte MAC address is ignored (corner)", { IFLA_ADDRESS, sizeof(nl_test_mac7), nl_test_mac7 },
      0, "goip0 index %u mtu 1500 admin-up link-up multiaccess broadcast multicast" },
    { "master not known yet (corner)", { IFLA_MASTER, sizeof(u32), &nl_test_master_missing },
      0, "goip0 index %u mtu 1500 admin-up link-up multiaccess broadcast multicast lladdr 5e:9c:8f:0b:ce:ae" },
    { "link kind vrf (positive)", { IFLA_LINKINFO, sizeof(nl_test_kind_vrf), nl_test_kind_vrf },
      0, "goip0 index %u mtu 1500 admin-up link-up multiaccess broadcast multicast vrf lladdr 5e:9c:8f:0b:ce:ae" },
    { "message one byte shorter than struct ifinfomsg (negative)", {},
      NLMSG_LENGTH(sizeof(struct ifinfomsg)) - 1, "none" },
    { "message with struct ifinfomsg and no attributes (boundary)", {},
      NLMSG_LENGTH(sizeof(struct ifinfomsg)), "none" },
  };

  struct nl_test_capture c;
  nl_test_load_links(&c);
  struct nlmsghdr *base = nl_test_find_link(&c, "goip0");

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    uint index = 100 + i;
    struct nlmsghdr *h = nl_test_copy(base, sizeof(struct ifinfomsg), &cases[i].attr);
    ((struct ifinfomsg *) NLMSG_DATA(h))->ifi_index = index;

    if (cases[i].msg_len)
      h->nlmsg_len = cases[i].msg_len;

    nl_parse_link(h, 0);

    char expected[256];
    bsnprintf(expected, sizeof(expected), cases[i].expected, index);
    nl_test_check_iface(cases[i].description, if_find_by_index(index), expected);
    xfree(h);
  }

  nl_test_free(&c);

  return 1;
}

/* Changes to links already known, applied in order */
static int
t_parse_link_update(void)
{
  static const struct {
    const char *description;
    const char *base;		/* Captured link to start from */
    u16 type;
    uint index;			/* ifi_index to send and look up */
    const char *name;		/* New name, or NULL */
    uint flags_clear;		/* ifi_flags bits to clear */
    const char *expected;
  } cases[] = {
    { "link set down", "goip0", RTM_NEWLINK, 3, NULL, IFF_UP | IFF_LOWER_UP,
      "goip0 index 3 mtu 1500 multiaccess broadcast multicast lladdr 5e:9c:8f:0b:ce:ae" },
    { "link set up again", "goip0", RTM_NEWLINK, 3, NULL, 0,
      "goip0 index 3 mtu 1500 admin-up link-up multiaccess broadcast multicast lladdr 5e:9c:8f:0b:ce:ae" },
    { "carrier lost", "goipv", RTM_NEWLINK, 5, NULL, IFF_LOWER_UP,
      "goipv index 5 mtu 1500 admin-up multiaccess broadcast multicast master goipvrf lladdr 86:da:71:5c:b3:da" },
    { "rename replaces the interface", "goip0", RTM_NEWLINK, 3, "goip1", 0,
      "goip1 index 3 mtu 1500 admin-up link-up multiaccess broadcast multicast lladdr 5e:9c:8f:0b:ce:ae" },
    { "deleted link is gone", "goipv", RTM_DELLINK, 5, NULL, 0,
      "none" },
    { "deleting a link twice (negative)", "goipv", RTM_DELLINK, 5, NULL, 0,
      "none" },
    { "deleting an unknown index (negative)", "nlmon0", RTM_DELLINK, 77, NULL, 0,
      "none" },
    { "the other links are untouched", "nlmon0", RTM_NEWLINK, 2, NULL, 0,
      "nlmon0 index 2 mtu 3776 admin-up link-up multiaccess" },
  };

  struct nl_test_capture c;
  nl_test_load_links(&c);

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    struct nl_test_attr rename = {};
    if (cases[i].name)
      rename = (struct nl_test_attr) { IFLA_IFNAME, strlen(cases[i].name) + 1, cases[i].name };

    struct nlmsghdr *h = nl_test_copy(nl_test_find_link(&c, cases[i].base), sizeof(struct ifinfomsg), &rename);
    struct ifinfomsg *ifi = NLMSG_DATA(h);
    h->nlmsg_type = cases[i].type;
    ifi->ifi_index = cases[i].index;
    ifi->ifi_flags &= ~cases[i].flags_clear;

    nl_parse_link(h, 0);
    nl_test_check_iface(cases[i].description, if_find_by_index(cases[i].index), cases[i].expected);
    xfree(h);
  }

  nl_test_free(&c);

  return 1;
}


/*
 *	Addresses
 */

/* if_recalc_preferred() asks the device protocol for interface options;
 * stand in for one configured without any */
static struct kif_config nl_test_kif_config;
static struct kif_proto nl_test_kif;

static void
nl_test_kif_init(void)
{
  init_list(&nl_test_kif_config.iface_list);
  nl_test_kif.p.cf = &nl_test_kif_config.c;
  kif_proto = &nl_test_kif;
}

/* The addresses of interface i, for comparing with a case's expected text:
 * "ip net prefix [brd b] [opposite o] scope s [flags]", separated by ", " */
static void
nl_test_format_addrs(struct iface *i, char *buf, uint size)
{
  static const struct { uint flag; const char *name; } flags[] = {
    { IA_PRIMARY, "primary" },
    { IA_SECONDARY, "secondary" },
    { IA_PEER, "peer" },
    { IA_HOST, "host" },
  };

  char *pos = buf;
  bsnprintf(buf, size, "none");

  if (!i)
    return;

  struct ifa *a;
  WALK_LIST(a, i->addrs)
  {
    if (pos != buf)
      pos += bsnprintf(pos, buf + size - pos, ", ");

    pos += bsnprintf(pos, buf + size - pos, "%I net %N", a->ip, &a->prefix);

    if (!ipa_zero(a->brd))
      pos += bsnprintf(pos, buf + size - pos, " brd %I", a->brd);

    if (!ipa_zero(a->opposite))
      pos += bsnprintf(pos, buf + size - pos, " opposite %I", a->opposite);

    pos += bsnprintf(pos, buf + size - pos, " scope %s", ip_scope_text(a->scope));

    for (uint j = 0; j < ARRAY_SIZE(flags); j++)
      if (a->flags & flags[j].flag)
	pos += bsnprintf(pos, buf + size - pos, " %s", flags[j].name);
  }
}

static int
nl_test_check_addrs(const char *description, struct iface *i, const char *expected)
{
  char got[1024];
  nl_test_format_addrs(i, got, sizeof(got));
  bt_assert_msg(!strcmp(got, expected), "%s: got \"%s\", expected \"%s\"", description, got, expected);
  return 1;
}

/* The captured RTM_NEWADDR message whose IFA_ADDRESS is addr */
static struct nlmsghdr *
nl_test_find_addr(struct nl_test_capture *c, const char *addr)
{
  for (uint i = 0; i < c->count; i++)
  {
    if (c->msg[i]->nlmsg_type != RTM_NEWADDR)
      continue;

    struct rtattr *a = nl_test_find_attr(c->msg[i], sizeof(struct ifaddrmsg), IFA_ADDRESS);
    char buf[64];
    if (a && (bsnprintf(buf, sizeof(buf), "%I", rta_get_ipa(a)) > 0) && !strcmp(buf, addr))
      return c->msg[i];
  }

  bt_abort_msg("No address %s in the capture", addr);
  return NULL;
}

/* A new interface like goip0 (broadcast, Ethernet), with the given index */
static struct iface *
nl_test_add_link(struct nl_test_capture *links, uint index)
{
  char name[16];
  bsnprintf(name, sizeof(name), "a%u", index);

  struct nl_test_attr rename = { IFLA_IFNAME, strlen(name) + 1, name };
  struct nlmsghdr *h = nl_test_copy(nl_test_find_link(links, "goip0"), sizeof(struct ifinfomsg), &rename);
  ((struct ifinfomsg *) NLMSG_DATA(h))->ifi_index = index;

  nl_parse_link(h, 0);
  xfree(h);

  struct iface *i = if_find_by_index(index);
  if (!i)
    bt_abort_msg("Link %s not created", name);

  return i;
}

/* The addresses of the capture, as `ip addr show` printed them:
 *
 *   1: lo       inet 127.0.0.1/8 scope host
 *               inet6 ::1/128 scope host
 *   2: nlmon0   (none)
 *   3: goip0    inet 192.0.2.1/24 brd 192.0.2.255 scope global
 *               inet6 2001:db8::9/64 scope global nodad mngtmpaddr noprefixroute
 *               inet6 2001:db8::1/64 scope global nodad
 *               inet6 fe80::5c9c:8fff:fe0b:ceae/64 scope link
 *   4: goipvrf  (none)
 *   5: goipv    inet 198.18.11.1/24 scope global
 *               inet6 fe80::84da:71ff:fe5c:b3da/64 scope link
 */
static int
t_parse_addr_capture(void)
{
  static const struct {
    const char *description;
    uint index;
    const char *expected;
  } cases[] = {
    { "loopback addresses have host scope", 1,
      "127.0.0.1 net 127.0.0.0/8 scope host primary, ::1 net ::1/128 brd ::1 scope host primary host" },
    { "link without addresses", 2,
      "none" },
    { "IPv4, two global IPv6 and a link-local address, the first of each is primary", 3,
      "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary, "
      "2001:db8::9 net 2001:db8::/64 scope univ primary, "
      "2001:db8::1 net 2001:db8::/64 scope univ, "
      "fe80::5c9c:8fff:fe0b:ceae net fe80::/64 scope link primary" },
    { "VRF device without addresses", 4,
      "none" },
    { "VRF member, IPv4 broadcast computed as the kernel sent none", 5,
      "198.18.11.1 net 198.18.11.0/24 brd 198.18.11.255 scope univ primary, "
      "fe80::84da:71ff:fe5c:b3da net fe80::/64 scope link primary" },
  };

  struct nl_test_capture links, addrs;
  nl_test_kif_init();
  nl_test_load_links(&links);
  nl_test_load(&addrs, "addr-dump.pcap");

  for (uint i = 0; i < addrs.count; i++)
    if (addrs.msg[i]->nlmsg_type == RTM_NEWADDR)
      nl_parse_addr(addrs.msg[i], 0);

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
    nl_test_check_addrs(cases[i].description, if_find_by_index(cases[i].index), cases[i].expected);

  nl_test_free(&links);
  nl_test_free(&addrs);

  return 1;
}

static const byte nl_test_ip4_peer[4] = { 192, 0, 2, 2 };
static const byte nl_test_ip4_zero[4] = { 0, 0, 0, 0 };
static const byte nl_test_ip4_short[3] = { 192, 0, 2 };
static const byte nl_test_ip6_local[16] = { 0x20, 0x01, 0x0d, 0xb8, [15] = 2 };
static const byte nl_test_ip6_ll[16] = { 0xfe, 0x80, [15] = 1 };
static const byte nl_test_ip6_mcast[16] = { 0xff, 0x0e, [15] = 1 };
static const u32 nl_test_ifa_secondary = IFA_F_SECONDARY;
static const u32 nl_test_ifa_tentative = IFA_F_TENTATIVE;

#define NL_KEEP	-1

/* Changed copies of goip0's 192.0.2.1/24 and 2001:db8::1/64 messages, each
 * sent to a new interface */
static int
t_parse_addr_changed(void)
{
  static const struct {
    const char *description;
    const char *base;		/* Captured address to start from */
    u16 type;
    int family;			/* ifa_family, or NL_KEEP */
    int prefixlen;		/* ifa_prefixlen, or NL_KEEP */
    int index;			/* ifa_index, or NL_KEEP for the case's interface */
    struct nl_test_attr attr;
    uint msg_len;		/* Truncate the message to this length, 0 keeps it */
    int preload;		/* Add the unchanged address first */
    const char *expected;
  } cases[] = {
    /* IPv4 */
    { "IPv4 unchanged copy (positive)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, {}, 0, 0,
      "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary" },
    { "IPv4 without IFA_BROADCAST gets a computed one (positive)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, { IFA_BROADCAST, NL_TEST_DROP }, 0, 0,
      "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary" },
    { "IPv4 secondary address is never primary (positive)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, { IFA_FLAGS, sizeof(u32), &nl_test_ifa_secondary }, 0, 0,
      "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ secondary" },
    { "IPv4 /32 host address (boundary)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, 32, NL_KEEP, {}, 0, 0,
      "192.0.2.1 net 192.0.2.1/32 brd 192.0.2.1 scope univ primary host" },
    { "IPv4 /32 peer address (boundary)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, 32, NL_KEEP, { IFA_ADDRESS, 4, nl_test_ip4_peer }, 0, 0,
      "192.0.2.1 net 192.0.2.2/32 brd 192.0.2.2 opposite 192.0.2.2 scope univ primary peer" },
    { "IPv4 /31 has an opposite and no computed broadcast (boundary)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, 31, NL_KEEP, { IFA_BROADCAST, NL_TEST_DROP }, 0, 0,
      "192.0.2.1 net 192.0.2.0/31 opposite 192.0.2.0 scope univ primary" },
    { "IPv4 /30 has an opposite (boundary)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, 30, NL_KEEP, { IFA_BROADCAST, NL_TEST_DROP }, 0, 0,
      "192.0.2.1 net 192.0.2.0/30 brd 192.0.2.3 opposite 192.0.2.2 scope univ primary" },
    { "IPv4 /0 (boundary)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, 0, NL_KEEP, { IFA_BROADCAST, NL_TEST_DROP }, 0, 0,
      "192.0.2.1 net 0.0.0.0/0 brd 255.255.255.255 scope univ primary" },
    { "IPv4 without IFA_LOCAL (negative)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, { IFA_LOCAL, NL_TEST_DROP }, 0, 0,
      "none" },
    { "IPv4 without IFA_ADDRESS (negative)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, { IFA_ADDRESS, NL_TEST_DROP }, 0, 0,
      "none" },
    { "IPv4 with a 3 byte IFA_LOCAL (negative)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, { IFA_LOCAL, 3, nl_test_ip4_short }, 0, 0,
      "none" },
    { "IPv4 0.0.0.0 is not an interface address (negative)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, { IFA_LOCAL, 4, nl_test_ip4_zero }, 0, 0,
      "none" },
    { "IPv4 for an unknown interface index (negative)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, NL_KEEP, 99, {}, 0, 0,
      "none" },
    { "unknown address family is ignored (negative)",
      "192.0.2.1", RTM_NEWADDR, AF_PACKET, NL_KEEP, NL_KEEP, {}, 0, 0,
      "none" },
    { "message one byte shorter than struct ifaddrmsg (negative)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, {}, NLMSG_LENGTH(sizeof(struct ifaddrmsg)) - 1, 0,
      "none" },
    { "message with struct ifaddrmsg and no attributes (boundary)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, {}, NLMSG_LENGTH(sizeof(struct ifaddrmsg)), 0,
      "none" },
    { "IPv4 added twice is kept once (corner)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, {}, 0, 1,
      "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary" },
    { "IPv4 deleted after being added (positive)",
      "192.0.2.1", RTM_DELADDR, NL_KEEP, NL_KEEP, NL_KEEP, {}, 0, 1,
      "none" },
    { "IPv4 deleted without being added (negative)",
      "192.0.2.1", RTM_DELADDR, NL_KEEP, NL_KEEP, NL_KEEP, {}, 0, 0,
      "none" },
    { "IPv4 deleted with another prefix length is kept (corner)",
      "192.0.2.1", RTM_DELADDR, NL_KEEP, 25, NL_KEEP, {}, 0, 1,
      "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary" },
    { "IPv4 prefix length 33 is rejected (negative)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, 33, NL_KEEP, {}, 0, 0,
      "none" },
    { "IPv4 prefix length 33 leaves the address alone (corner)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, 33, NL_KEEP, {}, 0, 1,
      "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary" },
    { "IPv4 prefix length 255 leaves the address alone (corner)",
      "192.0.2.1", RTM_NEWADDR, NL_KEEP, 255, NL_KEEP, {}, 0, 1,
      "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary" },
    { "IPv4 deleted with prefix length 33 is kept (corner)",
      "192.0.2.1", RTM_DELADDR, NL_KEEP, 33, NL_KEEP, {}, 0, 1,
      "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary" },

    /* IPv6 */
    { "IPv6 unchanged copy (positive)",
      "2001:db8::1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, {}, 0, 0,
      "2001:db8::1 net 2001:db8::/64 scope univ primary" },
    { "IPv6 IFA_LOCAL is the address when present (corner)",
      "2001:db8::1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, { IFA_LOCAL, 16, nl_test_ip6_local }, 0, 0,
      "2001:db8::2 net 2001:db8::/64 scope univ primary" },
    { "IPv6 link-local address (positive)",
      "2001:db8::1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, { IFA_ADDRESS, 16, nl_test_ip6_ll }, 0, 0,
      "fe80::1 net fe80::/64 scope link primary" },
    { "IPv6 multicast address, as added with IFA_F_MCAUTOJOIN, is kept (corner)",
      "2001:db8::1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, { IFA_ADDRESS, 16, nl_test_ip6_mcast }, 0, 0,
      "ff0e::1 net ff0e::/64 scope univ primary" },
    { "IPv6 /128 host address (boundary)",
      "2001:db8::1", RTM_NEWADDR, NL_KEEP, 128, NL_KEEP, {}, 0, 0,
      "2001:db8::1 net 2001:db8::1/128 brd 2001:db8::1 scope univ primary host" },
    { "IPv6 /127 has an opposite (boundary)",
      "2001:db8::1", RTM_NEWADDR, NL_KEEP, 127, NL_KEEP, {}, 0, 0,
      "2001:db8::1 net 2001:db8::/127 opposite 2001:db8:: scope univ primary" },
    { "IPv6 /0 (boundary)",
      "2001:db8::1", RTM_NEWADDR, NL_KEEP, 0, NL_KEEP, {}, 0, 0,
      "2001:db8::1 net ::/0 scope univ primary" },
    { "IPv6 tentative address is ignored (negative)",
      "2001:db8::1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, { IFA_FLAGS, sizeof(u32), &nl_test_ifa_tentative }, 0, 0,
      "none" },
    { "IPv6 without IFA_ADDRESS (negative)",
      "2001:db8::1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, { IFA_ADDRESS, NL_TEST_DROP }, 0, 0,
      "none" },
    { "IPv6 with a 4 byte IFA_ADDRESS (negative)",
      "2001:db8::1", RTM_NEWADDR, NL_KEEP, NL_KEEP, NL_KEEP, { IFA_ADDRESS, 4, nl_test_ip4_peer }, 0, 0,
      "none" },
    { "IPv6 deleted after being added (positive)",
      "2001:db8::1", RTM_DELADDR, NL_KEEP, NL_KEEP, NL_KEEP, {}, 0, 1,
      "none" },
    { "IPv6 prefix length 129 is rejected (negative)",
      "2001:db8::1", RTM_NEWADDR, NL_KEEP, 129, NL_KEEP, {}, 0, 0,
      "none" },
    { "IPv6 prefix length 129 leaves the address alone (corner)",
      "2001:db8::1", RTM_NEWADDR, NL_KEEP, 129, NL_KEEP, {}, 0, 1,
      "2001:db8::1 net 2001:db8::/64 scope univ primary" },
    { "IPv6 prefix length 255 leaves the address alone (corner)",
      "2001:db8::1", RTM_NEWADDR, NL_KEEP, 255, NL_KEEP, {}, 0, 1,
      "2001:db8::1 net 2001:db8::/64 scope univ primary" },
  };

  struct nl_test_capture links, addrs;
  nl_test_kif_init();
  nl_test_load_links(&links);
  nl_test_load(&addrs, "addr-dump.pcap");

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    uint index = 100 + i;
    struct iface *ifi = nl_test_add_link(&links, index);
    struct nlmsghdr *base = nl_test_find_addr(&addrs, cases[i].base);

    if (cases[i].preload)
    {
      struct nlmsghdr *h = nl_test_copy(base, sizeof(struct ifaddrmsg), &(struct nl_test_attr) {});
      ((struct ifaddrmsg *) NLMSG_DATA(h))->ifa_index = index;
      nl_parse_addr(h, 0);
      xfree(h);
    }

    struct nlmsghdr *h = nl_test_copy(base, sizeof(struct ifaddrmsg), &cases[i].attr);
    struct ifaddrmsg *ifa = NLMSG_DATA(h);
    h->nlmsg_type = cases[i].type;
    ifa->ifa_index = (cases[i].index == NL_KEEP) ? index : (uint) cases[i].index;

    if (cases[i].family != NL_KEEP)
      ifa->ifa_family = cases[i].family;

    if (cases[i].prefixlen != NL_KEEP)
      ifa->ifa_prefixlen = cases[i].prefixlen;

    if (cases[i].msg_len)
      h->nlmsg_len = cases[i].msg_len;

    nl_parse_addr(h, 0);
    nl_test_check_addrs(cases[i].description, ifi, cases[i].expected);
    xfree(h);
  }

  nl_test_free(&links);
  nl_test_free(&addrs);

  return 1;
}


int
main(int argc, char *argv[])
{
  bt_init(argc, argv);
  bt_bird_init();

  /* The captures are of a little-endian host, and netlink messages are in
   * host byte order */
#ifdef CPU_BIG_ENDIAN
  bt_debug("The captures are little-endian, skipping their tests\n");
  return bt_exit_value();
#endif

  bt_test_suite(t_parse_link_capture, "Links from a captured link dump");
  bt_test_suite(t_parse_link_changed, "Links with one attribute changed");
  bt_test_suite(t_parse_link_update, "Changes to known links");
  bt_test_suite(t_parse_addr_capture, "Addresses from a captured address dump");
  bt_test_suite(t_parse_addr_changed, "Addresses with one field or attribute changed");

  return bt_exit_value();
}
