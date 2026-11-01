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

/* nl_parse_route() hands routes to these; record them instead */
#define krt_got_route		nl_test_got_route
#define krt_got_route_async	nl_test_got_route_async

/* No netlink sockets and no scans of the host, see below */
#define krt_sys_start		nl_test_unused_krt_sys_start
#define krt_do_scan		nl_test_unused_krt_do_scan
#define kif_sys_start		nl_test_unused_kif_sys_start
#define kif_do_scan		nl_test_unused_kif_do_scan

/* The same for the bridge protocol: record what the FDB and VLAN parsers
 * hand to it, with no netlink sockets and no scans */
#define kbr_got_fdb		nl_test_got_fdb
#define kbr_got_vlan		nl_test_got_vlan
#define kbr_got_vlan_tunnel	nl_test_got_vlan_tunnel
#define kbr_sys_start		nl_test_unused_kbr_sys_start
#define kbr_do_fdb_scan		nl_test_unused_kbr_do_fdb_scan
#define kbr_do_vlan_scan	nl_test_unused_kbr_do_vlan_scan

/* nl_error() logs with this; record it instead */
struct tbf;
void nl_test_log_rl(struct tbf *rl, const char *msg, ...);
#define log_rl			nl_test_log_rl

#include "sysdep/linux/netlink.c"

#undef log_rl
#undef krt_got_route
#undef krt_got_route_async
#undef krt_sys_start
#undef krt_do_scan
#undef kif_sys_start
#undef kif_do_scan
#undef kbr_got_fdb
#undef kbr_got_vlan
#undef kbr_got_vlan_tunnel
#undef kbr_sys_start
#undef kbr_do_fdb_scan
#undef kbr_do_vlan_scan

int krt_sys_start(struct krt_proto *p);
void krt_do_scan(struct krt_proto *p);
void kif_sys_start(struct kif_proto *p);
void kif_do_scan(struct kif_proto *p);

/* Only register the kernel table, as the real one does before opening
 * the sockets */
int
krt_sys_start(struct krt_proto *p)
{
  if (HASH_FIND(nl_table_map, RTH, p->af, krt_table_id(p)))
    return 0;

  HASH_INSERT2(nl_table_map, RTH, krt_pool, p);
  return 1;
}

void krt_do_scan(struct krt_proto *p UNUSED) { }
void kif_sys_start(struct kif_proto *p UNUSED) { }
void kif_do_scan(struct kif_proto *p UNUSED) { }

#ifdef CONFIG_BRIDGE
int kbr_sys_start(struct kbr_proto *p);
void kbr_do_fdb_scan(struct kbr_proto *p);
void kbr_do_vlan_scan(struct kbr_proto *p);

/* Only register the bridge, as the real one does before opening the
 * sockets */
int
kbr_sys_start(struct kbr_proto *p)
{
  if (HASH_FIND(nl_bridge_map, BRH, kbr_bridge_id(p)))
    return 0;

  HASH_INSERT2(nl_bridge_map, BRH, krt_pool, p);
  return 1;
}

void kbr_do_fdb_scan(struct kbr_proto *p UNUSED) { }
void kbr_do_vlan_scan(struct kbr_proto *p UNUSED) { }
#endif

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
 * attribute), padded as the kernel pads messages, in an exactly sized
 * buffer */
static struct nlmsghdr *
nl_test_copy(struct nlmsghdr *h, uint hlen, const struct nl_test_attr *m)
{
  uint size = NLMSG_ALIGN(h->nlmsg_len) + (m->len > 0 ? RTA_SPACE(m->len) : 0);
  struct nlmsghdr *n = alloca(size);
  int found = 0;

  memset(n, 0, size);

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

  n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len);

  struct nlmsghdr *copy = xmalloc(n->nlmsg_len);
  memcpy(copy, n, n->nlmsg_len);
  return copy;
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

  ea_list *attrs = i->attrs ? i->attrs->eattrs : NULL;
  if (ea_get_int(attrs, EA_IFACE_TYPE, IF_TYPE_UNDEF) == IF_TYPE_BRIDGE)
    pos += bsnprintf(pos, buf + size - pos, " bridge");

  u32 vlan_filtering = ea_get_int(attrs, EA_IFACE_BRIDGE_VLAN_FILTERING, U32_UNDEF);
  if (vlan_filtering != U32_UNDEF)
    pos += bsnprintf(pos, buf + size - pos, " vlan-filtering %u", vlan_filtering);

  if (ea_get_int(attrs, EA_IFACE_TYPE, IF_TYPE_UNDEF) == IF_TYPE_VXLAN)
    pos += bsnprintf(pos, buf + size - pos, " vxlan");

  u32 vni = ea_get_int(attrs, EA_IFACE_VXLAN_ID, U32_UNDEF);
  if (vni != U32_UNDEF)
    pos += bsnprintf(pos, buf + size - pos, " vni %u", vni);

  u32 learning = ea_get_int(attrs, EA_IFACE_VXLAN_LEARNING, U32_UNDEF);
  if (learning != U32_UNDEF)
    pos += bsnprintf(pos, buf + size - pos, " learning %u", learning);

  eattr *ea = ea_find(attrs, EA_IFACE_VXLAN_IP_ADDR);
  if (ea)
    pos += bsnprintf(pos, buf + size - pos, " local %I", *(ip_addr *) ea->u.ptr->data);

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
static const byte nl_test_kind_vrf_no_nul[] = {
  /* IFLA_INFO_KIND "vrf" without its NUL, the last byte is padding */
  7, 0, IFLA_INFO_KIND, 0, 'v', 'r', 'f', 0,
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
    { "name without a NUL is rejected (negative)", { IFLA_IFNAME, 4, "eth1" },
      0, "none" },
    { "name with its NUL only in the padding is rejected (corner)", { IFLA_IFNAME, 3, "abc" },
      0, "none" },
    { "15 character name without a NUL is rejected (boundary)", { IFLA_IFNAME, 15, nl_test_name15 },
      0, "none" },
    { "name ends at its first NUL (corner)", { IFLA_IFNAME, 4, "ab\0c" },
      0, "ab index %u mtu 1500 admin-up link-up multiaccess broadcast multicast lladdr 5e:9c:8f:0b:ce:ae" },
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
    { "link kind without a NUL is ignored (negative)", { IFLA_LINKINFO, sizeof(nl_test_kind_vrf_no_nul), nl_test_kind_vrf_no_nul },
      0, "goip0 index %u mtu 1500 admin-up link-up multiaccess broadcast multicast lladdr 5e:9c:8f:0b:ce:ae" },
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
 * A bridge's link message built in host byte order, unlike the captures,
 * so that this also runs on big-endian hosts: IFLA_BR_VLAN_FILTERING of
 * len bytes (none if 0), with value in its first byte and pad in the rest
 * of its 4 aligned bytes
 */
static struct nlmsghdr *
nl_test_bridge_msg(uint len, byte value, byte pad)
{
  uint size = 256;
  struct nlmsghdr *h = alloca(size);
  memset(h, 0, size);

  h->nlmsg_type = RTM_NEWLINK;
  h->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

  struct ifinfomsg *i = NLMSG_DATA(h);
  i->ifi_family = AF_UNSPEC;
  i->ifi_type = ARPHRD_ETHER;
  i->ifi_index = 50;
  i->ifi_flags = IFF_UP | IFF_BROADCAST | IFF_MULTICAST;

  nl_add_attr(h, size, IFLA_IFNAME, "nb0", 4);
  nl_add_attr_u32(h, size, IFLA_MTU, 1500);

  struct rtattr *li = nl_open_attr(h, size, IFLA_LINKINFO);
  nl_add_attr(h, size, IFLA_INFO_KIND, "bridge", 7);
  struct rtattr *data = nl_open_attr(h, size, IFLA_INFO_DATA);

  if (len)
  {
    byte buf[4] = { value, pad, pad, pad };
    struct rtattr *a = nl_add_attr(h, size, IFLA_BR_VLAN_FILTERING, buf, len);
    memcpy(RTA_DATA(a), buf, 4);
  }

  nl_close_attr(h, data);
  nl_close_attr(h, li);
  h->nlmsg_len = NLMSG_ALIGN(h->nlmsg_len);

  struct nlmsghdr *copy = xmalloc(h->nlmsg_len);
  memcpy(copy, h, h->nlmsg_len);
  return copy;
}

#define NL_BR_IFACE	"nb0 index 50 mtu 1500 admin-up multiaccess broadcast multicast bridge"

/* The kernel sends IFLA_BR_VLAN_FILTERING as a u8 */
static int
t_parse_link_bridge(void)
{
  static const struct {
    const char *description;
    uint len;
    byte value;
    byte pad;
    const char *expected;
  } cases[] = {
    { "VLAN filtering on (positive)", 1, 1, 0,
      NL_BR_IFACE " vlan-filtering 1" },
    { "VLAN filtering off (positive)", 1, 0, 0,
      NL_BR_IFACE " vlan-filtering 0" },
    { "VLAN filtering on, padding set (corner)", 1, 1, 0xff,
      NL_BR_IFACE " vlan-filtering 1" },
    { "VLAN filtering off, padding set (corner)", 1, 0, 0xff,
      NL_BR_IFACE " vlan-filtering 0" },
    { "VLAN filtering 255 is passed on (boundary)", 1, 255, 0,
      NL_BR_IFACE " vlan-filtering 255" },
    { "VLAN filtering of 4 bytes is not taken (negative)", 4, 1, 0,
      NL_BR_IFACE },
    { "no VLAN filtering attribute (negative)", 0, 0, 0,
      NL_BR_IFACE },
  };

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    struct nlmsghdr *h = nl_test_bridge_msg(cases[i].len, cases[i].value, cases[i].pad);
    nl_parse_link(h, 0);
    nl_test_check_iface(cases[i].description, if_find_by_index(50), cases[i].expected);
    xfree(h);
  }

  return 1;
}


/*
 * Links of other kinds, from xtcp2's link-write kinds corpus (see README):
 * each row created one link (index 3, after lo and nlmon0, or 4 after a
 * dummy d0) and read back "ip -d link show". The links are down.
 */
static int
t_parse_link_kinds(void)
{
  static const struct {
    const char *description;
    const char *row;		/* kinds row, see README */
    const char *name;
    const char *expected;
  } cases[] = {
    { "kinds/vxlan/add_default: ip link add vx0 type vxlan id 42",
      "vxlan/add_default", "vx0",
      "vx0 index 3 mtu 1500 multiaccess broadcast multicast vxlan vni 42 learning 1 lladdr a2:af:d3:fa:9d:cf" },
    { "kinds/vxlan/add_local: vxlan id 42 local 10.0.0.1",
      "vxlan/add_local", "vx0",
      "vx0 index 3 mtu 1500 multiaccess broadcast multicast vxlan vni 42 learning 1 local 10.0.0.1 lladdr 26:26:85:4f:60:77" },
    { "kinds/vxlan/add_local6_link_local: vxlan id 42 local fe80::1 dev d0, index 4",
      "vxlan/add_local6_link_local", "vx0",
      "vx0 index 4 mtu 1430 multiaccess broadcast multicast vxlan vni 42 learning 1 local fe80::1 lladdr 72:e8:27:5f:cc:a5" },
    { "kinds/vxlan/add_remote6: vxlan id 42 remote 2001:db8::1, no local address",
      "vxlan/add_remote6", "vx0",
      "vx0 index 3 mtu 1500 multiaccess broadcast multicast vxlan vni 42 learning 1 lladdr 86:92:7c:0b:78:95" },
    { "kinds/vxlan/add_external: vxlan external, id 0 and nolearning",
      "vxlan/add_external", "vx0",
      "vx0 index 3 mtu 1500 multiaccess broadcast multicast vxlan vni 0 learning 0 lladdr 7a:76:fc:4f:6c:66" },
    { "kinds/vxlan/add_nolearning: vxlan id 42 nolearning",
      "vxlan/add_nolearning", "vx0",
      "vx0 index 3 mtu 1500 multiaccess broadcast multicast vxlan vni 42 learning 0 lladdr 6a:f6:9c:64:75:c4" },
    { "kinds/vxlan/add_id_max: vxlan id 16777215, the highest (boundary)",
      "vxlan/add_id_max", "vx0",
      "vx0 index 3 mtu 1500 multiaccess broadcast multicast vxlan vni 16777215 learning 1 lladdr e6:43:11:8b:b6:fd" },
    { "kinds/vxlan/add_id_zero: vxlan id 0, the lowest (boundary)",
      "vxlan/add_id_zero", "vx0",
      "vx0 index 3 mtu 1500 multiaccess broadcast multicast vxlan vni 0 learning 1 lladdr 06:dc:d3:a8:57:3c" },
    { "kinds/vxlan/add_vnifilter: vxlan external vnifilter (corner)",
      "vxlan/add_vnifilter", "vx0",
      "vx0 index 3 mtu 1500 multiaccess broadcast multicast vxlan vni 0 learning 0 lladdr 7e:06:42:c0:be:4f" },
    { "kinds/gre/add_local: gre local 10.0.0.2, NOARP, neither point-to-point nor broadcast",
      "gre/add_local", "gr0",
      "gr0 index 3 mtu 1476 multiaccess" },
    { "kinds/ipip/add_local: ipip remote 10.0.0.1 local 10.0.0.2, point-to-point",
      "ipip/add_local", "ip0",
      "ip0 index 3 mtu 1480 multicast" },
    { "kinds/sit/add_default: sit remote 10.0.0.1, point-to-point",
      "sit/add_default", "st0",
      "st0 index 3 mtu 1480 multicast" },
    { "kinds/vti/add_default: vti remote 10.0.0.1 local 10.0.0.2, point-to-point",
      "vti/add_default", "vt0",
      "vt0 index 3 mtu 1480 multicast" },
  };

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    struct nl_test_capture c;
    char name[128];

    bsnprintf(name, sizeof(name), "kinds/%s/netlink_route_getlink_detail.pcap", cases[i].row);
    nl_test_load(&c, name);

    /* The last one: ip first looks the link up by name, with a reply of
     * only IFLA_IFNAME */
    struct nlmsghdr *h = NULL;
    for (uint j = 0; j < c.count; j++)
      if ((c.msg[j]->nlmsg_type == RTM_NEWLINK) && !strcmp(nl_test_link_name(c.msg[j]), cases[i].name))
	h = c.msg[j];

    if (!h)
      bt_abort_msg("No link %s in the capture", cases[i].name);

    struct ifinfomsg *ifi = NLMSG_DATA(h);
    nl_parse_link(h, 0);
    nl_test_check_iface(cases[i].description, if_find_by_index(ifi->ifi_index), cases[i].expected);

    /* Gone again, for the next row's link of the same index */
    h->nlmsg_type = RTM_DELLINK;
    nl_parse_link(h, 0);

    nl_test_free(&c);
  }

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

/*
 * The addresses of xtcp2's link-write addr-show rows (see README): each row
 * added addresses to a dummy d0 (index 3, after lo and nlmon0) or other
 * links, then ran "ip addr show", whose dump has the links and addresses.
 * The links are parsed, then the addresses, then all is deleted again, in
 * reverse, for the next row's links of the same names.
 *
 * The rows under ws/ are of xtcp2's ip address matrix: one "ip address"
 * command on a dummy d0 (3, addrgenmode none), then "ip address show dev
 * d0", whose dump (netlink_route_dump.pcap) has d0 and its addresses.
 */
static int
t_parse_addr_show(void)
{
  static const struct {
    const char *description;
    const char *row;		/* addr-show or ws row, see README */
    const char *name;
    const char *expected;
  } cases[] = {
    /* IPv4 */
    { "v4_secondary: 192.0.2.1/24 and 192.0.2.2/24, the second one secondary (positive)",
      "v4_secondary", "d0",
      "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary, "
      "192.0.2.2 net 192.0.2.0/24 brd 192.0.2.255 scope univ secondary" },
    { "v4_label: 192.0.2.1/24 label d0:1 and 192.0.2.9/24 label d0:9, labels ignored (positive)",
      "v4_label", "d0",
      "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary, "
      "192.0.2.9 net 192.0.2.0/24 brd 192.0.2.255 scope univ secondary" },
    { "v4_peer: 10.0.0.1 peer 10.0.0.2/32, private so scope site (boundary)",
      "v4_peer", "d0", "10.0.0.1 net 10.0.0.2/32 brd 10.0.0.2 opposite 10.0.0.2 scope site primary peer" },
    { "v4_brd: brd +, brd - (198.51.100.0, trusted) and a /31 with brd + (corner)",
      "v4_brd", "d0",
      "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary, "
      "198.51.100.1 net 198.51.100.0/24 brd 198.51.100.0 scope univ, "
      "203.0.113.0 net 203.0.113.0/31 opposite 203.0.113.1 scope univ" },
    { "v4_host_scope: 127.0.0.2/8, scope host (corner)",
      "v4_host_scope", "d0", "127.0.0.2 net 127.0.0.0/8 brd 127.255.255.255 scope host primary" },
    { "v4_autojoin: 224.0.0.251/32 autojoin, a multicast address taken as a host address (corner)",
      "v4_autojoin", "d0", "224.0.0.251 net 224.0.0.251/32 brd 224.0.0.251 scope univ primary host" },
    { "v4_deprecated: 192.0.2.1/24 preferred_lft 0, deprecated (corner)",
      "v4_deprecated", "d0", "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary" },
    { "v4_lifetimes: 192.0.2.1/24 valid_lft 3600 preferred_lft 1800, dynamic (positive)",
      "v4_lifetimes", "d0", "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary" },
    { "v4_metric: 192.0.2.1/24 metric 50, IFA_RT_PRIORITY ignored (positive)",
      "v4_metric", "d0", "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary" },
    { "v4_proto: proto 99 and proto kernel_lo, IFA_PROTO ignored (positive)",
      "v4_proto", "d0",
      "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary, "
      "198.51.100.1 net 198.51.100.0/24 brd 198.51.100.255 scope univ" },
    { "v4_vrf: d0 in vrf0 (index 4) with 192.0.2.1/24",
      "v4_vrf", "d0", "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary" },
    { "v4_vrf: d1 (index 5) with 198.51.100.1/24",
      "v4_vrf", "d1", "198.51.100.1 net 198.51.100.0/24 brd 198.51.100.255 scope univ primary" },
    { "v4_vrf: vrf0 (index 3) without addresses",
      "v4_vrf", "vrf0", "none" },
    { "mixed_links: d0 up with 192.0.2.1/24",
      "mixed_links", "d0", "192.0.2.1 net 192.0.2.0/24 brd 192.0.2.255 scope univ primary" },
    { "mixed_links: d1 down with 198.51.100.1/24",
      "mixed_links", "d1", "198.51.100.1 net 198.51.100.0/24 brd 198.51.100.255 scope univ primary" },
    { "mixed_links: d2 up without addresses",
      "mixed_links", "d2", "none" },
    { "mixed_links: d3, a bond0 port, with 203.0.113.1/24",
      "mixed_links", "d3", "203.0.113.1 net 203.0.113.0/24 brd 203.0.113.255 scope univ primary" },
    { "mixed_links: bond0 without addresses",
      "mixed_links", "bond0", "none" },
    { "ws/addr4/bd-003: 192.0.2.1/0 scope 255 (nowhere) preferred_lft 0, a /0 kept and its scope taken from the address (boundary)",
      "ws/addr4/bd-003", "d0", "192.0.2.1 net 0.0.0.0/0 brd 255.255.255.255 scope univ primary" },
    { "ws/addr4/ec-002: 192.0.2.1 peer 198.51.100.1/32 broadcast 192.0.2.255 scope link noprefixroute, scope taken from the address (corner)",
      "ws/addr4/ec-002", "d0", "192.0.2.1 net 198.51.100.1/32 brd 198.51.100.1 opposite 198.51.100.1 scope univ primary peer" },

    /* IPv6 */
    { "v6_flags: nodad, home, mngtmpaddr noprefixroute and a /48 (positive)",
      "v6_flags", "d0",
      "2001:db8:3::1 net 2001:db8:3::/48 scope univ primary, "
      "2001:db8:2::1 net 2001:db8:2::/64 scope univ, "
      "2001:db8:1::1 net 2001:db8:1::/64 scope univ, "
      "2001:db8::1 net 2001:db8::/64 scope univ" },
    { "v6_peer: 2001:db8::1 peer 2001:db8::2/128 (boundary)",
      "v6_peer", "d0", "2001:db8::1 net 2001:db8::2/128 brd 2001:db8::2 opposite 2001:db8::2 scope univ primary peer" },
    { "v6_temporary: a temporary address, IFA_F_TEMPORARY taken as IFA_F_SECONDARY (corner)",
      "v6_temporary", "d0",
      "2001:db8::fbed:f0b4:1fd0:cabe net 2001:db8::/64 scope univ secondary, "
      "2001:db8::1 net 2001:db8::/64 scope univ primary" },
    { "v6_stable_privacy: link-local address of addrgenmode random (positive)",
      "v6_stable_privacy", "d0", "fe80::c764:67be:9f7a:f3f3 net fe80::/64 scope link primary" },
    { "v6_tentative: 2001:db8::5/64 tentative, ignored (negative)",
      "v6_tentative", "v0", "none" },
    { "v6_optimistic: optimistic tentative addresses, ignored (negative)",
      "v6_optimistic", "v0", "none" },
    { "v6_optimistic: v1, a tentative link-local address, ignored (negative)",
      "v6_optimistic", "v1", "none" },
    { "v6_dadfailed: dadfailed tentative and a tentative link-local address, ignored (negative)",
      "v6_dadfailed", "v0", "none" },
    { "ws/addr6/bd-002: 2001:db8:1::1/0 metric 4294967295 proto 255, a /0 kept (boundary)",
      "ws/addr6/bd-002", "d0", "2001:db8:1::1 net ::/0 scope univ primary" },
  };

  nl_test_kif_init();

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    struct nl_test_capture c;
    char name[128];

    if (!strncmp(cases[i].row, "ws/", 3))
      bsnprintf(name, sizeof(name), "%s/netlink_route_dump.pcap", cases[i].row);
    else
      bsnprintf(name, sizeof(name), "addr-show/%s/netlink_route_getaddr.pcap", cases[i].row);
    nl_test_load(&c, name);

    for (uint j = 0; j < c.count; j++)
      if (c.msg[j]->nlmsg_type == RTM_NEWLINK)
	nl_parse_link(c.msg[j], 0);

    for (uint j = 0; j < c.count; j++)
      if (c.msg[j]->nlmsg_type == RTM_NEWADDR)
	nl_parse_addr(c.msg[j], 0);

    struct ifinfomsg *ifi = NLMSG_DATA(nl_test_find_link(&c, cases[i].name));
    nl_test_check_addrs(cases[i].description, if_find_by_index(ifi->ifi_index), cases[i].expected);

    /* Gone again, for the next row's links */
    for (uint j = c.count; j--; )
      if (c.msg[j]->nlmsg_type == RTM_NEWADDR)
      {
	c.msg[j]->nlmsg_type = RTM_DELADDR;
	nl_parse_addr(c.msg[j], 0);
      }

    for (uint j = c.count; j--; )
      if (c.msg[j]->nlmsg_type == RTM_NEWLINK)
      {
	c.msg[j]->nlmsg_type = RTM_DELLINK;
	nl_parse_link(c.msg[j], 0);
      }

    nl_test_free(&c);
  }

  return 1;
}


/*
 *	Routes
 */

/* Kernel protocols for the tables of the capture: main (254) and the VRF's
 * table 100, both families. The local table (255) is left out. */
#define NL_TEST_ROUTE_CONFIG						\
  "router id 192.0.2.1;\n"						\
  "ipv4 table t4v;\n"							\
  "ipv6 table t6v;\n"							\
  "protocol device { scan time 86400; }\n"				\
  "protocol kernel k4 { ipv4 { import all; }; learn all; scan time 86400; }\n" \
  "protocol kernel k6 { ipv6 { import all; }; learn all; scan time 86400; }\n" \
  "protocol kernel k4v { ipv4 { table t4v; import all; }; kernel table 100; learn all; scan time 86400; }\n" \
  "protocol kernel k6v { ipv6 { table t6v; import all; }; kernel table 100; learn all; scan time 86400; }\n"

/* What the parser handed to the kernel protocols, one route per entry,
 * separated by "; " */
static char nl_test_routes[4096];
static char *nl_test_routes_pos;

static void
nl_test_routes_reset(void)
{
  nl_test_routes_pos = nl_test_routes;
  bsnprintf(nl_test_routes, sizeof(nl_test_routes), "none");
}

#define NL_TEST_ROUTES_END	(nl_test_routes + sizeof(nl_test_routes))

static void
nl_test_routes_add(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  nl_test_routes_pos += bvsnprintf(nl_test_routes_pos, NL_TEST_ROUTES_END - nl_test_routes_pos, fmt, args);
  va_end(args);
}

/* "proto mode net source proto P metric M dest [next hops] [attributes]" */
static void
nl_test_record_route(struct krt_proto *p, rte *e, const char *mode, s8 src)
{
  static const char *srcs[] = {
    [KRT_SRC_BIRD] = "bird",
    [KRT_SRC_REDIRECT] = "redirect",
    [KRT_SRC_ALIEN] = "alien",
    [KRT_SRC_KERNEL] = "kernel",
  };

  static const char *dests[] = {
    [RTD_UNICAST] = "unicast",
    [RTD_BLACKHOLE] = "blackhole",
    [RTD_UNREACHABLE] = "unreachable",
    [RTD_PROHIBIT] = "prohibit",
  };

  static const char *metrics[KRT_METRICS_MAX] = {
    [RTAX_LOCK] = "lock",
    [RTAX_MTU] = "mtu",
    [RTAX_WINDOW] = "window",
    [RTAX_RTT] = "rtt",
    [RTAX_RTTVAR] = "rttvar",
    [RTAX_SSTHRESH] = "ssthresh",
    [RTAX_CWND] = "cwnd",
    [RTAX_ADVMSS] = "advmss",
    [RTAX_REORDERING] = "reordering",
    [RTAX_HOPLIMIT] = "hoplimit",
    [RTAX_INITCWND] = "initcwnd",
    [RTAX_FEATURES] = "features",
    [RTAX_RTO_MIN] = "rto_min",
    [RTAX_INITRWND] = "initrwnd",
    [RTAX_QUICKACK] = "quickack",
    [RTAX_CC_ALGO] = "congctl",
    [RTAX_FASTOPEN_NO_COOKIE] = "fastopen_no_cookie",
  };

  rta *a = e->attrs;
  eattr *ea;

  if (nl_test_routes_pos != nl_test_routes)
    nl_test_routes_add("; ");
  else
    nl_test_routes[0] = 0;

  nl_test_routes_add("%s %s %N %s", p->p.name, mode, e->net->n.addr,
		     ((src >= 0) && (src < (int) ARRAY_SIZE(srcs)) && srcs[src]) ? srcs[src] : "?");

  if (ea = ea_find(a->eattrs, EA_KRT_SOURCE))
    nl_test_routes_add(" proto %u", ea->u.data);

  if (ea = ea_find(a->eattrs, EA_KRT_METRIC))
    nl_test_routes_add(" metric %u", ea->u.data);

  nl_test_routes_add(" %s", (a->dest < ARRAY_SIZE(dests)) && dests[a->dest] ? dests[a->dest] : "?");

  if (a->dest == RTD_UNICAST)
    for (struct nexthop *nh = &a->nh; nh; nh = nh->next)
    {
      if (ipa_nonzero(nh->gw))
	nl_test_routes_add(" via %I", nh->gw);

      nl_test_routes_add(" dev %s", nh->iface ? nh->iface->name : "?");

      for (uint l = 0; l < nh->labels; l++)
	nl_test_routes_add("%s%u", l ? "/" : " labels ", nh->label[l]);

      if (a->nh.next)
	nl_test_routes_add(" weight %u", nh->weight + 1);

      if (nh->flags & RNF_ONLINK)
	nl_test_routes_add(" onlink");
    }

  if (ea = ea_find(a->eattrs, EA_KRT_SCOPE))
    nl_test_routes_add(" scope %u", ea->u.data);

  if (ea = ea_find(a->eattrs, EA_KRT_PREFSRC))
    nl_test_routes_add(" prefsrc %I", *(ip_addr *) ea->u.ptr->data);

  if (ea = ea_find(a->eattrs, EA_KRT_REALM))
    nl_test_routes_add(" realm %u", ea->u.data);

  for (uint t = 1; t < KRT_METRICS_MAX; t++)
    if (ea = ea_find(a->eattrs, EA_KRT_METRICS + t))
    {
      if (t == RTAX_CC_ALGO)
	nl_test_routes_add(" %s %s", metrics[t], (const char *) ea->u.ptr->data);
      else
	nl_test_routes_add(" %s %u", metrics[t], ea->u.data);
    }
}

void nl_test_got_route(struct krt_proto *p, rte *e, s8 src);
void nl_test_got_route_async(struct krt_proto *p, rte *e, int new, s8 src);

void
nl_test_got_route(struct krt_proto *p, rte *e, s8 src)
{
  nl_test_record_route(p, e, "scan", src);
}

void
nl_test_got_route_async(struct krt_proto *p, rte *e, int new, s8 src)
{
  nl_test_record_route(p, e, new ? "add" : "del", src);
}

/* Destination and table of route message h, as "table N net" */
static void
nl_test_route_key(struct nlmsghdr *h, char *buf, uint size)
{
  struct rtmsg *r = NLMSG_DATA(h);
  struct rtattr *a = nl_test_find_attr(h, sizeof(struct rtmsg), RTA_TABLE);
  u32 table = a ? rta_get_u32(a) : r->rtm_table;

  net_addr n;
  a = nl_test_find_attr(h, sizeof(struct rtmsg), RTA_DST);

  if (r->rtm_family == AF_INET)
    net_fill_ip4(&n, a ? rta_get_ip4(a) : IP4_NONE, r->rtm_dst_len);
  else if (r->rtm_family == AF_INET6)
    net_fill_ip6(&n, a ? rta_get_ip6(a) : IP6_NONE, r->rtm_dst_len);
  else
  {
    u32 stack[MPLS_MAX_LABEL_STACK];
    net_fill_mpls(&n, (a && (mpls_get(RTA_DATA(a), RTA_PAYLOAD(a), stack) > 0)) ? stack[0] : 0);
  }

  /* Keep local and broadcast routes apart from unicast ones */
  const char *type = (r->rtm_type == RTN_LOCAL) ? "local " :
    (r->rtm_type == RTN_BROADCAST) ? "broadcast " :
    (r->rtm_type == RTN_MULTICAST) ? "multicast " : "";

  bsnprintf(buf, size, "table %u %s%N", table, type, &n);
}

/* The captured route message with key `key` (see nl_test_route_key()) */
static struct nlmsghdr *
nl_test_find_route(struct nl_test_capture *c, const char *key)
{
  for (uint i = 0; i < c->count; i++)
  {
    char buf[128];
    if (c->msg[i]->nlmsg_type != RTM_NEWROUTE)
      continue;

    nl_test_route_key(c->msg[i], buf, sizeof(buf));
    if (!strcmp(buf, key))
      return c->msg[i];
  }

  bt_abort_msg("No route %s in the capture", key);
  return NULL;
}

/* Kernel protocols up, the captured links and addresses known */
/* Run the events a new configuration queued, which start the protocols */
static void
nl_test_pump(void)
{
  for (int i = 0; i < 256; i++)
  {
    if (EMPTY_LIST(global_event_list) && EMPTY_LIST(global_work_list))
      break;

    ev_run_list(&global_event_list);
    ev_run_list(&global_work_list);
  }
}

static void
nl_test_route_setup_config(const char *config)
{
  struct nl_test_capture links, addrs;

  bt_assert_msg(bt_config_parse(config), "Route test config");
  nl_test_pump();

  nl_test_load_links(&links);
  nl_test_load(&addrs, "addr-dump.pcap");

  for (uint i = 0; i < addrs.count; i++)
    if (addrs.msg[i]->nlmsg_type == RTM_NEWADDR)
      nl_parse_addr(addrs.msg[i], 0);

  nl_test_free(&links);
  nl_test_free(&addrs);
}

static void
nl_test_route_setup(void)
{
  nl_test_route_setup_config(NL_TEST_ROUTE_CONFIG);
}

static void
nl_test_parse_route(struct nlmsghdr *h, int scan)
{
  struct nl_parse_state s = {
    .pool = nl_linpool,
    .scan = scan,
  };

  nl_test_routes_reset();
  nl_parse_route(&s, h);
}

static int
nl_test_check_routes(const char *description, const char *expected)
{
  bt_assert_msg(!strcmp(nl_test_routes, expected), "%s: got \"%s\", expected \"%s\"",
		description, nl_test_routes, expected);
  return 1;
}

/* The routes of the capture, as `ip route show table all` printed them */
static int
t_parse_route_capture(void)
{
  static const struct {
    const char *description;
    const char *key;		/* See nl_test_route_key() */
    const char *expected;
  } cases[] = {
    /* VRF table 100 */
    { "198.18.11.0/24 dev goipv table 100 proto kernel scope link src 198.18.11.1",
      "table 100 198.18.11.0/24",
      "k4v scan 198.18.11.0/24 kernel proto 2 metric 0 unicast dev goipv scope 253 prefsrc 198.18.11.1" },
    { "local 198.18.11.1 dev goipv table 100: local routes are skipped",
      "table 100 local 198.18.11.1/32", "none" },
    { "broadcast 198.18.11.255 dev goipv table 100: broadcast routes are skipped",
      "table 100 broadcast 198.18.11.255/32", "none" },
    { "local fe80::84da:71ff:fe5c:b3da dev goipv table 100: link scope, skipped",
      "table 100 local fe80::84da:71ff:fe5c:b3da/128", "none" },
    { "fe80::/64 dev goipv table 100: link scope, skipped",
      "table 100 fe80::/64", "none" },
    { "multicast ff00::/8 dev goipv table 100: multicast, skipped",
      "table 100 multicast ff00::/8", "none" },

    /* Main table */
    { "192.0.2.0/24 dev goip0 proto kernel scope link src 192.0.2.1",
      "table 254 192.0.2.0/24",
      "k4 scan 192.0.2.0/24 kernel proto 2 metric 0 unicast dev goip0 scope 253 prefsrc 192.0.2.1" },
    { "198.18.0.0/24 via 192.0.2.10 dev goip0",
      "table 254 198.18.0.0/24",
      "k4 scan 198.18.0.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev goip0" },
    { "198.18.1.0/24 via 192.0.2.10 dev goip0 mtu 1400 advmss 1300",
      "table 254 198.18.1.0/24",
      "k4 scan 198.18.1.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev goip0 mtu 1400 advmss 1300" },
    { "198.18.2.0/24 via inet6 2001:db8::2 dev goip0",
      "table 254 198.18.2.0/24",
      "k4 scan 198.18.2.0/24 alien proto 3 metric 0 unicast via 2001:db8::2 dev goip0" },
    { "198.18.3.0/24 nhid 1 via 192.0.2.10 dev goip0",
      "table 254 198.18.3.0/24",
      "k4 scan 198.18.3.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev goip0" },
    { "198.51.100.0/24 dev goip0 scope link",
      "table 254 198.51.100.0/24",
      "k4 scan 198.51.100.0/24 alien proto 3 metric 0 unicast dev goip0 scope 253" },
    { "203.0.113.0/24 nexthop via 192.0.2.10 weight 1, nexthop via 192.0.2.11 weight 3, sorted",
      "table 254 203.0.113.0/24",
      "k4 scan 203.0.113.0/24 alien proto 3 metric 0 unicast via 192.0.2.11 dev goip0 weight 3 via 192.0.2.10 dev goip0 weight 1" },
    { "2001:db8::/64 dev goip0 proto kernel metric 256",
      "table 254 2001:db8::/64",
      "k6 scan 2001:db8::/64 kernel proto 2 metric 256 unicast dev goip0" },
    { "2001:db8:1::/64 via 2001:db8::2 dev goip0 metric 1024",
      "table 254 2001:db8:1::/64",
      "k6 scan 2001:db8:1::/64 alien proto 3 metric 1024 unicast via 2001:db8::2 dev goip0" },
    { "2001:db8:2::/64 metric 1024 nexthop via 2001:db8::2 weight 1, nexthop via 2001:db8::3 weight 3, sorted",
      "table 254 2001:db8:2::/64",
      "k6 scan 2001:db8:2::/64 alien proto 3 metric 1024 unicast via 2001:db8::3 dev goip0 weight 3 via 2001:db8::2 dev goip0 weight 1" },
    { "2001:db8:4::/64 from 2001:db8:5::/64 dev goip0: source prefix on a non-SADR channel, skipped",
      "table 254 2001:db8:4::/64", "none" },
    { "fe80::/64 dev goip0: link scope, skipped",
      "table 254 fe80::/64", "none" },

    /* Local table, which no kernel protocol is configured for */
    { "local 127.0.0.0/8 dev lo table local",
      "table 255 local 127.0.0.0/8", "none" },
    { "local 127.0.0.1 dev lo table local",
      "table 255 local 127.0.0.1/32", "none" },
    { "broadcast 127.255.255.255 dev lo table local",
      "table 255 broadcast 127.255.255.255/32", "none" },
    { "local 192.0.2.1 dev goip0 table local",
      "table 255 local 192.0.2.1/32", "none" },
    { "broadcast 192.0.2.255 dev goip0 table local",
      "table 255 broadcast 192.0.2.255/32", "none" },
    { "local ::1 dev lo table local",
      "table 255 local ::1/128", "none" },
    { "local 2001:db8::1 dev goip0 table local",
      "table 255 local 2001:db8::1/128", "none" },
    { "local 2001:db8::9 dev goip0 table local",
      "table 255 local 2001:db8::9/128", "none" },
    { "local fe80::5c9c:8fff:fe0b:ceae dev goip0 table local",
      "table 255 local fe80::5c9c:8fff:fe0b:ceae/128", "none" },
    { "multicast ff00::/8 dev goip0 table local",
      "table 255 multicast ff00::/8", "none" },
  };

  struct nl_test_capture routes;
  nl_test_route_setup();
  nl_test_load(&routes, "route-dump.pcap");

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    nl_test_parse_route(nl_test_find_route(&routes, cases[i].key), 1);
    nl_test_check_routes(cases[i].description, cases[i].expected);
  }

  /* Every captured route has a case */
  for (uint i = 0; i < routes.count; i++)
  {
    char key[128];
    if (routes.msg[i]->nlmsg_type != RTM_NEWROUTE)
      continue;

    nl_test_route_key(routes.msg[i], key, sizeof(key));

    int found = 0;
    for (uint j = 0; j < ARRAY_SIZE(cases); j++)
      found |= !strcmp(cases[j].key, key);

    bt_assert_msg(found, "No case for captured route %s", key);
  }

  nl_test_free(&routes);

  return 1;
}

/* An IPv6 SADR channel for the main table, which takes source prefixes */
#define NL_TEST_SADR_CONFIG						\
  "router id 192.0.2.1;\n"						\
  "ipv6 sadr table s6;\n"						\
  "protocol device { scan time 86400; }\n"				\
  "protocol kernel k6s { ipv6 sadr { table s6; import all; }; learn all; scan time 86400; }\n"

/* IPv6 routes of the capture on a SADR channel */
static int
t_parse_route_sadr(void)
{
  static const struct {
    const char *description;
    const char *key;		/* See nl_test_route_key() */
    const char *expected;
  } cases[] = {
    { "2001:db8:4::/64 from 2001:db8:5::/64 dev goip0: source prefix kept",
      "table 254 2001:db8:4::/64",
      "k6s scan 2001:db8:4::/64 from 2001:db8:5::/64 alien proto 3 metric 1024 unicast dev goip0" },
    { "2001:db8:1::/64 via 2001:db8::2 dev goip0 metric 1024: no source prefix, from ::/0",
      "table 254 2001:db8:1::/64",
      "k6s scan 2001:db8:1::/64 from ::/0 alien proto 3 metric 1024 unicast via 2001:db8::2 dev goip0" },
    { "2001:db8:2::/64 multipath: no source prefix, from ::/0",
      "table 254 2001:db8:2::/64",
      "k6s scan 2001:db8:2::/64 from ::/0 alien proto 3 metric 1024 unicast via 2001:db8::3 dev goip0 weight 3 via 2001:db8::2 dev goip0 weight 1" },
    { "198.18.0.0/24 via 192.0.2.10 dev goip0: IPv4, no IPv4 channel",
      "table 254 198.18.0.0/24", "none" },
    { "fe80::/64 dev goip0: link scope, skipped",
      "table 254 fe80::/64", "none" },
  };

  struct nl_test_capture routes;
  nl_test_route_setup_config(NL_TEST_SADR_CONFIG);
  nl_test_load(&routes, "route-dump.pcap");

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    nl_test_parse_route(nl_test_find_route(&routes, cases[i].key), 1);
    nl_test_check_routes(cases[i].description, cases[i].expected);
  }

  nl_test_free(&routes);

  return 1;
}

/* A field of struct rtmsg to change */
enum nl_test_rtm_field {
  NL_RTM_NONE,
  NL_RTM_FAMILY,
  NL_RTM_DST_LEN,
  NL_RTM_TOS,
  NL_RTM_PROTOCOL,
  NL_RTM_TYPE,
  NL_RTM_FLAGS,			/* Bits to set */
};

struct nl_test_rtm {
  enum nl_test_rtm_field field;
  uint value;
};

static void
nl_test_rtm_apply(struct rtmsg *r, const struct nl_test_rtm *m)
{
  switch (m->field)
  {
  case NL_RTM_NONE:	break;
  case NL_RTM_FAMILY:	r->rtm_family = m->value; break;
  case NL_RTM_DST_LEN:	r->rtm_dst_len = m->value; break;
  case NL_RTM_TOS:	r->rtm_tos = m->value; break;
  case NL_RTM_PROTOCOL:	r->rtm_protocol = m->value; break;
  case NL_RTM_TYPE:	r->rtm_type = m->value; break;
  case NL_RTM_FLAGS:	r->rtm_flags |= m->value; break;
  }
}

#define NL_V4		"table 254 198.18.0.0/24"
#define NL_V4_EXP	"k4 scan 198.18.0.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev goip0"
#define NL_V4_VIA	"table 254 198.18.2.0/24"
#define NL_V4_METRICS	"table 254 198.18.1.0/24"
#define NL_V6		"table 254 2001:db8:1::/64"
#define NL_V6_EXP	"k6 scan 2001:db8:1::/64 alien proto 3 metric 1024 unicast via 2001:db8::2 dev goip0"

static const u32 nl_test_u32_3 = 3;
static const u32 nl_test_u32_7 = 7;
static const u32 nl_test_u32_42 = 42;
static const u32 nl_test_u32_77 = 77;
static const u32 nl_test_u32_100 = 100;
static const u32 nl_test_u32_max = 0xffffffff;
static const byte nl_test_gw4_offlink[4] = { 203, 0, 113, 1 };
static const byte nl_test_gw4_self[4] = { 192, 0, 2, 1 };
static const byte nl_test_dst4_mcast[4] = { 224, 0, 0, 0 };
static const byte nl_test_gw6_v4mapped[16] = { [12] = 192, 0, 2, 10 };
static const byte nl_test_gw6_ll[16] = { 0xfe, 0x80, [15] = 1 };

/* struct rtvia: a host order u16 family, then the address */
static const byte nl_test_via4[6] = { AF_INET, 0, 192, 0, 2, 10 };
static const byte nl_test_via6_short[6] = { AF_INET6, 0, 0x20, 0x01, 0x0d, 0xb8 };
static const byte nl_test_via_family[2] = { AF_INET6, 0 };
static const byte nl_test_via_unknown[6] = { AF_PACKET, 0, 192, 0, 2, 10 };

/* Nested RTA_METRICS attributes: struct rtattr (u16 length, u16 type), data */
static const byte nl_test_metrics_cc[] = {
  10, 0, RTAX_CC_ALGO, 0, 'c', 'u', 'b', 'i', 'c', 0, 0, 0,
};
static const byte nl_test_metrics_cc_unterminated[] = {
  9, 0, RTAX_CC_ALGO, 0, 'c', 'u', 'b', 'i', 'c', 0, 0, 0,
};
static const byte nl_test_metrics_lock[] = {
  8, 0, RTAX_LOCK, 0, 1 << RTAX_MTU, 0, 0, 0,
  8, 0, RTAX_MTU, 0, 0xdc, 0x05, 0, 0,
};
static const byte nl_test_metrics_short[] = {
  6, 0, RTAX_MTU, 0, 0xdc, 0x05, 0, 0,
};
static const byte nl_test_metrics_unknown[] = {
  8, 0, 0x7f, 0, 1, 0, 0, 0,
};

/* Changed copies of captured routes, through a kernel protocol scan
 * unless async is set */
static int
t_parse_route_changed(void)
{
  static const struct {
    const char *description;
    const char *base;		/* Captured route to start from, see nl_test_route_key() */
    int async;			/* As a notification, not in a scan */
    int del;			/* As RTM_DELROUTE */
    struct nl_test_rtm rtm;
    struct nl_test_attr attr;
    uint msg_len;		/* Truncate the message to this length, 0 keeps it */
    const char *expected;
  } cases[] = {
    /* Sources and modes */
    { .description = "unchanged copy (positive)", .base = NL_V4,
      .expected = NL_V4_EXP },
    { .description = "notification of a new route (positive)", .base = NL_V4, .async = 1,
      .expected = "k4 add 198.18.0.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev goip0" },
    { .description = "notification of a removed route (positive)", .base = NL_V4, .async = 1, .del = 1,
      .expected = "k4 del 198.18.0.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev goip0" },
    { .description = "RTM_DELROUTE in a scan is ignored (negative)", .base = NL_V4, .del = 1,
      .expected = "none" },
    { .description = "proto kernel (positive)", .base = NL_V4, .rtm = { NL_RTM_PROTOCOL, RTPROT_KERNEL },
      .expected = "k4 scan 198.18.0.0/24 kernel proto 2 metric 0 unicast via 192.0.2.10 dev goip0" },
    { .description = "proto redirect (positive)", .base = NL_V4, .rtm = { NL_RTM_PROTOCOL, RTPROT_REDIRECT },
      .expected = "k4 scan 198.18.0.0/24 redirect proto 1 metric 0 unicast via 192.0.2.10 dev goip0" },
    { .description = "proto bird in a scan is our own route (positive)", .base = NL_V4, .rtm = { NL_RTM_PROTOCOL, RTPROT_BIRD },
      .expected = "k4 scan 198.18.0.0/24 bird proto 12 metric 0 unicast via 192.0.2.10 dev goip0" },
    { .description = "proto bird notification is our own echo (negative)", .base = NL_V4, .async = 1, .rtm = { NL_RTM_PROTOCOL, RTPROT_BIRD },
      .expected = "none" },
    { .description = "proto unspec is ignored (negative)", .base = NL_V4, .rtm = { NL_RTM_PROTOCOL, RTPROT_UNSPEC },
      .expected = "none" },
    { .description = "proto 255, unknown to BIRD, is alien (boundary)", .base = NL_V4, .rtm = { NL_RTM_PROTOCOL, 255 },
      .expected = "k4 scan 198.18.0.0/24 alien proto 255 metric 0 unicast via 192.0.2.10 dev goip0" },

    /* Route types and flags */
    { .description = "blackhole (positive)", .base = NL_V4, .rtm = { NL_RTM_TYPE, RTN_BLACKHOLE },
      .expected = "k4 scan 198.18.0.0/24 alien proto 3 metric 0 blackhole" },
    { .description = "unreachable (positive)", .base = NL_V4, .rtm = { NL_RTM_TYPE, RTN_UNREACHABLE },
      .expected = "k4 scan 198.18.0.0/24 alien proto 3 metric 0 unreachable" },
    { .description = "prohibit (positive)", .base = NL_V4, .rtm = { NL_RTM_TYPE, RTN_PROHIBIT },
      .expected = "k4 scan 198.18.0.0/24 alien proto 3 metric 0 prohibit" },
    { .description = "throw is not supported (negative)", .base = NL_V4, .rtm = { NL_RTM_TYPE, RTN_THROW },
      .expected = "none" },
    { .description = "TOS is not supported (negative)", .base = NL_V4, .rtm = { NL_RTM_TOS, 4 },
      .expected = "none" },
    { .description = "cloned route is ignored (negative)", .base = NL_V4, .rtm = { NL_RTM_FLAGS, RTM_F_CLONED },
      .expected = "none" },
    { .description = "dead next hop is ignored (negative)", .base = NL_V4, .rtm = { NL_RTM_FLAGS, RTNH_F_DEAD },
      .expected = "none" },
    { .description = "onlink next hop (positive)", .base = NL_V4, .rtm = { NL_RTM_FLAGS, RTNH_F_ONLINK },
      .expected = "k4 scan 198.18.0.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev goip0 onlink" },
    { .description = "unknown address family (negative)", .base = NL_V4, .rtm = { NL_RTM_FAMILY, AF_PACKET },
      .expected = "none" },

    /* Destination */
    { .description = "/32 (boundary)", .base = NL_V4, .rtm = { NL_RTM_DST_LEN, 32 },
      .expected = "k4 scan 198.18.0.0/32 alien proto 3 metric 0 unicast via 192.0.2.10 dev goip0" },
    { .description = "default route, no RTA_DST (boundary)", .base = NL_V4, .rtm = { NL_RTM_DST_LEN, 0 }, .attr = { RTA_DST, NL_TEST_DROP },
      .expected = "k4 scan 0.0.0.0/0 alien proto 3 metric 0 unicast via 192.0.2.10 dev goip0" },
    { .description = "multicast destination (negative)", .base = NL_V4, .attr = { RTA_DST, 4, nl_test_dst4_mcast },
      .expected = "none" },
    { .description = "3 byte RTA_DST (negative)", .base = NL_V4, .attr = { RTA_DST, 3, nl_test_dst4_mcast },
      .expected = "none" },

    /* Tables, interface and next hop */
    { .description = "RTA_TABLE 100 goes to that table's protocol (positive)", .base = NL_V4, .attr = { RTA_TABLE, 4, &nl_test_u32_100 },
      .expected = "k4v scan 198.18.0.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev goip0" },
    { .description = "unknown table (negative)", .base = NL_V4, .attr = { RTA_TABLE, 4, &nl_test_u32_42 },
      .expected = "none" },
    { .description = "unknown output interface (negative)", .base = NL_V4, .attr = { RTA_OIF, 4, &nl_test_u32_77 },
      .expected = "none" },
    { .description = "no output interface (negative)", .base = NL_V4, .attr = { RTA_OIF, NL_TEST_DROP },
      .expected = "none" },
    { .description = "gateway not on the link (negative)", .base = NL_V4, .attr = { RTA_GATEWAY, 4, nl_test_gw4_offlink },
      .expected = "none" },
    { .description = "gateway is our own address (negative)", .base = NL_V4, .attr = { RTA_GATEWAY, 4, nl_test_gw4_self },
      .expected = "none" },

    /* Attributes */
    { .description = "metric 2^32-1 (boundary)", .base = NL_V4, .attr = { RTA_PRIORITY, 4, &nl_test_u32_max },
      .expected = "k4 scan 198.18.0.0/24 alien proto 3 metric 4294967295 unicast via 192.0.2.10 dev goip0" },
    { .description = "preferred source (positive)", .base = NL_V4, .attr = { RTA_PREFSRC, 4, nl_test_gw4_self },
      .expected = NL_V4_EXP " prefsrc 192.0.2.1" },
    { .description = "realm (positive)", .base = NL_V4, .attr = { RTA_FLOW, 4, &nl_test_u32_7 },
      .expected = NL_V4_EXP " realm 7" },
    { .description = "congestion control algorithm (positive)", .base = NL_V4_METRICS, .attr = { RTA_METRICS, sizeof(nl_test_metrics_cc), nl_test_metrics_cc },
      .expected = "k4 scan 198.18.1.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev goip0 congctl cubic" },
    { .description = "locked MTU (positive)", .base = NL_V4_METRICS, .attr = { RTA_METRICS, sizeof(nl_test_metrics_lock), nl_test_metrics_lock },
      .expected = "k4 scan 198.18.1.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev goip0 lock 4 mtu 1500" },
    { .description = "empty RTA_METRICS (boundary)", .base = NL_V4_METRICS, .attr = { RTA_METRICS, 0, NULL },
      .expected = "k4 scan 198.18.1.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev goip0" },
    { .description = "unknown metric is ignored (corner)", .base = NL_V4_METRICS, .attr = { RTA_METRICS, sizeof(nl_test_metrics_unknown), nl_test_metrics_unknown },
      .expected = "k4 scan 198.18.1.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev goip0" },
    { .description = "2 byte metric (negative)", .base = NL_V4_METRICS, .attr = { RTA_METRICS, sizeof(nl_test_metrics_short), nl_test_metrics_short },
      .expected = "none" },
    { .description = "unterminated congestion control algorithm (negative)", .base = NL_V4_METRICS, .attr = { RTA_METRICS, sizeof(nl_test_metrics_cc_unterminated), nl_test_metrics_cc_unterminated },
      .expected = "none" },

    /* RTA_VIA */
    { .description = "RTA_VIA with an IPv6 next hop (positive)", .base = NL_V4_VIA,
      .expected = "k4 scan 198.18.2.0/24 alien proto 3 metric 0 unicast via 2001:db8::2 dev goip0" },
    { .description = "RTA_VIA with an IPv4 next hop (positive)", .base = NL_V4_VIA, .attr = { RTA_VIA, sizeof(nl_test_via4), nl_test_via4 },
      .expected = "k4 scan 198.18.2.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev goip0" },
    { .description = "RTA_VIA with a short IPv6 address gives no next hop (negative)", .base = NL_V4_VIA, .attr = { RTA_VIA, sizeof(nl_test_via6_short), nl_test_via6_short },
      .expected = "k4 scan 198.18.2.0/24 alien proto 3 metric 0 unicast dev goip0" },
    { .description = "RTA_VIA with only the family gives no next hop (boundary)", .base = NL_V4_VIA, .attr = { RTA_VIA, sizeof(nl_test_via_family), nl_test_via_family },
      .expected = "k4 scan 198.18.2.0/24 alien proto 3 metric 0 unicast dev goip0" },
    { .description = "empty RTA_VIA gives no next hop (boundary)", .base = NL_V4_VIA, .attr = { RTA_VIA, 0, NULL },
      .expected = "k4 scan 198.18.2.0/24 alien proto 3 metric 0 unicast dev goip0" },
    { .description = "RTA_VIA with an unknown family gives no next hop (corner)", .base = NL_V4_VIA, .attr = { RTA_VIA, sizeof(nl_test_via_unknown), nl_test_via_unknown },
      .expected = "k4 scan 198.18.2.0/24 alien proto 3 metric 0 unicast dev goip0" },

    /* Truncated */
    { .description = "message one byte shorter than struct rtmsg (negative)", .base = NL_V4,
      .msg_len = NLMSG_LENGTH(sizeof(struct rtmsg)) - 1, .expected = "none" },
    { .description = "message with struct rtmsg and no attributes (boundary)", .base = NL_V4,
      .msg_len = NLMSG_LENGTH(sizeof(struct rtmsg)), .expected = "none" },

    /* IPv6 */
    { .description = "IPv6 unchanged copy (positive)", .base = NL_V6,
      .expected = NL_V6_EXP },
    { .description = "IPv6 /128 (boundary)", .base = NL_V6, .rtm = { NL_RTM_DST_LEN, 128 },
      .expected = "k6 scan 2001:db8:1::/128 alien proto 3 metric 1024 unicast via 2001:db8::2 dev goip0" },
    { .description = "IPv6 link-local gateway (positive)", .base = NL_V6, .attr = { RTA_GATEWAY, 16, nl_test_gw6_ll },
      .expected = "k6 scan 2001:db8:1::/64 alien proto 3 metric 1024 unicast via fe80::1 dev goip0" },
    { .description = "IPv6 gateway in ::/96, as 6to4 tunnels have, is skipped (corner)", .base = NL_V6, .attr = { RTA_GATEWAY, 16, nl_test_gw6_v4mapped },
      .expected = "none" },
    { .description = "IPv6 with an input interface (negative)", .base = NL_V6, .attr = { RTA_IIF, 4, &nl_test_u32_3 },
      .expected = "none" },
  };

  struct nl_test_capture routes;
  nl_test_route_setup();
  nl_test_load(&routes, "route-dump.pcap");

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    struct nlmsghdr *h = nl_test_copy(nl_test_find_route(&routes, cases[i].base), sizeof(struct rtmsg), &cases[i].attr);
    h->nlmsg_type = cases[i].del ? RTM_DELROUTE : RTM_NEWROUTE;
    nl_test_rtm_apply(NLMSG_DATA(h), &cases[i].rtm);

    if (cases[i].msg_len)
      h->nlmsg_len = cases[i].msg_len;

    nl_test_parse_route(h, !cases[i].async);
    nl_test_check_routes(cases[i].description, cases[i].expected);
    xfree(h);
  }

  nl_test_free(&routes);

  return 1;
}


/*
 *	Multipath routes
 */

#define NL_MP4		"table 254 203.0.113.0/24"
#define NL_MP4_PFX	"k4 scan 203.0.113.0/24 alien proto 3 metric 0 unicast"
#define NL_MP6		"table 254 2001:db8:2::/64"
#define NL_MP6_PFX	"k6 scan 2001:db8:2::/64 alien proto 3 metric 1024 unicast"

#define NL_NH_ZERO	-1		/* A length of 0, as 0 means the built one */

struct nl_test_nh {
  int len;			/* rtnh_len; 0 uses the built length */
  byte flags;
  byte hops;			/* Weight - 1 */
  int ifindex;
  struct nl_test_attr attr;	/* RTA_GATEWAY or RTA_VIA, type 0 for none */
};

#define NL_GW4(x)	{ RTA_GATEWAY, 4, x }
#define NL_GW6(x)	{ RTA_GATEWAY, 16, x }

/* Build an RTA_MULTIPATH payload of next hops nh[0..n), up to the first
 * unset one, into buf; return its length */
static int
nl_test_multipath(byte *buf, uint size, const struct nl_test_nh *nh, uint n)
{
  uint pos = 0;

  memset(buf, 0, size);

  for (uint i = 0; (i < n) && (nh[i].ifindex || nh[i].len); i++)
  {
    struct rtnexthop *r = (void *) (buf + pos);
    uint len = RTNH_LENGTH(nh[i].attr.type ? RTA_SPACE(nh[i].attr.len) : 0);

    if (pos + RTNH_ALIGN(len) > size)
      bt_abort_msg("Multipath buffer too small");

    r->rtnh_len = (nh[i].len == NL_NH_ZERO) ? 0 : nh[i].len ? (uint) nh[i].len : len;
    r->rtnh_flags = nh[i].flags;
    r->rtnh_hops = nh[i].hops;
    r->rtnh_ifindex = nh[i].ifindex;

    if (nh[i].attr.type)
    {
      struct rtattr *a = RTNH_DATA(r);
      a->rta_type = nh[i].attr.type;
      a->rta_len = RTA_LENGTH(nh[i].attr.len);
      memcpy(RTA_DATA(a), nh[i].attr.data, nh[i].attr.len);
    }

    pos += RTNH_ALIGN(len);
  }

  return pos;
}

static const byte nl_test_gw4_a[4] = { 192, 0, 2, 10 };
static const byte nl_test_gw4_b[4] = { 192, 0, 2, 11 };
static const byte nl_test_gw4_c[4] = { 192, 0, 2, 12 };
static const byte nl_test_gw4_vrf[4] = { 198, 18, 11, 2 };
static const byte nl_test_gw6_a[16] = { 0x20, 0x01, 0x0d, 0xb8, [15] = 2 };
static const byte nl_test_gw6_b[16] = { 0x20, 0x01, 0x0d, 0xb8, [15] = 3 };
static const byte nl_test_via6[18] = { AF_INET6, 0, 0x20, 0x01, 0x0d, 0xb8, [17] = 2 };

static int
t_parse_route_multipath(void)
{
  static const struct {
    const char *description;
    const char *base;		/* Captured multipath route whose RTA_MULTIPATH is replaced */
    struct nl_test_nh nh[3];
    int payload;		/* RTA_MULTIPATH payload length; 0 uses the built one */
    const char *expected;
  } cases[] = {
    /* IPv4 */
    { .description = "two next hops as captured, sorted (positive)", .base = NL_MP4,
      .nh = { { .hops = 0, .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) },
	      { .hops = 2, .ifindex = 3, .attr = NL_GW4(nl_test_gw4_b) } },
      .expected = NL_MP4_PFX " via 192.0.2.11 dev goip0 weight 3 via 192.0.2.10 dev goip0 weight 1" },
    { .description = "one next hop (boundary)", .base = NL_MP4,
      .nh = { { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) } },
      .expected = NL_MP4_PFX " via 192.0.2.10 dev goip0" },
    { .description = "three next hops (positive)", .base = NL_MP4,
      .nh = { { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) },
	      { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_b) },
	      { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_c) } },
      .expected = NL_MP4_PFX " via 192.0.2.10 dev goip0 weight 1 via 192.0.2.11 dev goip0 weight 1 via 192.0.2.12 dev goip0 weight 1" },
    { .description = "next hop without a gateway (positive)", .base = NL_MP4,
      .nh = { { .ifindex = 3 }, { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) } },
      .expected = NL_MP4_PFX " dev goip0 weight 1 via 192.0.2.10 dev goip0 weight 1" },
    { .description = "weight 256, the largest (boundary)", .base = NL_MP4,
      .nh = { { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) },
	      { .hops = 255, .ifindex = 3, .attr = NL_GW4(nl_test_gw4_b) } },
      .expected = NL_MP4_PFX " via 192.0.2.11 dev goip0 weight 256 via 192.0.2.10 dev goip0 weight 1" },
    { .description = "next hop on a VRF member interface (corner)", .base = NL_MP4,
      .nh = { { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) },
	      { .ifindex = 5, .attr = NL_GW4(nl_test_gw4_vrf) } },
      .expected = NL_MP4_PFX " via 192.0.2.10 dev goip0 weight 1 via 198.18.11.2 dev goipv weight 1" },
    { .description = "RTA_VIA with an IPv6 gateway (positive)", .base = NL_MP4,
      .nh = { { .ifindex = 3, .attr = { RTA_VIA, sizeof(nl_test_via6), nl_test_via6 } } },
      .expected = NL_MP4_PFX " via 2001:db8::2 dev goip0" },
    { .description = "off-link gateway with RTNH_F_ONLINK (positive)", .base = NL_MP4,
      .nh = { { .flags = RTNH_F_ONLINK, .ifindex = 3, .attr = NL_GW4(nl_test_gw4_offlink) } },
      .expected = NL_MP4_PFX " via 203.0.113.1 dev goip0 onlink" },
    { .description = "off-link gateway is a strange next hop (negative)", .base = NL_MP4,
      .nh = { { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_offlink) } },
      .expected = "none" },
    { .description = "own address as gateway is a strange next hop (negative)", .base = NL_MP4,
      .nh = { { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) },
	      { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_self) } },
      .expected = "none" },
    { .description = "unknown ifindex (negative)", .base = NL_MP4,
      .nh = { { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) },
	      { .ifindex = 99, .attr = NL_GW4(nl_test_gw4_b) } },
      .expected = "none" },
    { .description = "gateway of 3 bytes (negative)", .base = NL_MP4,
      .nh = { { .ifindex = 3, .attr = { RTA_GATEWAY, 3, nl_test_gw4_a } } },
      .expected = "none" },
    { .description = "dead next hop is skipped (corner)", .base = NL_MP4,
      .nh = { { .flags = RTNH_F_DEAD, .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) },
	      { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_b) } },
      .expected = NL_MP4_PFX " via 192.0.2.11 dev goip0" },
    { .description = "only dead next hops (corner)", .base = NL_MP4,
      .nh = { { .flags = RTNH_F_DEAD, .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) } },
      .expected = "none" },
    { .description = "dead next hop with rtnh_len of 0 (negative)", .base = NL_MP4,
      .nh = { { .len = NL_NH_ZERO, .flags = RTNH_F_DEAD, .ifindex = 3 },
	      { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) } },
      .expected = "none" },
    { .description = "dead next hop with rtnh_len shorter than struct rtnexthop (negative)", .base = NL_MP4,
      .nh = { { .len = sizeof(struct rtnexthop) - 4, .flags = RTNH_F_DEAD, .ifindex = 3 },
	      { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) } },
      .expected = "none" },
    { .description = "dead next hop with rtnh_len longer than the payload (negative)", .base = NL_MP4,
      .nh = { { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) },
	      { .len = 64, .flags = RTNH_F_DEAD, .ifindex = 3 } },
      .expected = "none" },
    { .description = "last dead next hop with unaligned rtnh_len up to the end (corner)", .base = NL_MP4,
      .nh = { { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) },
	      { .len = sizeof(struct rtnexthop) + 1, .flags = RTNH_F_DEAD, .ifindex = 3 } },
      .payload = 16 + sizeof(struct rtnexthop) + 1,
      .expected = NL_MP4_PFX " via 192.0.2.10 dev goip0" },
    { .description = "empty payload (boundary)", .base = NL_MP4,
      .payload = NL_NH_ZERO, .expected = "none" },
    { .description = "payload shorter than struct rtnexthop (negative)", .base = NL_MP4,
      .nh = { { .ifindex = 3 } }, .payload = sizeof(struct rtnexthop) - 1,
      .expected = "none" },
    { .description = "rtnh_len of exactly struct rtnexthop (boundary)", .base = NL_MP4,
      .nh = { { .len = sizeof(struct rtnexthop), .ifindex = 3 } },
      .expected = NL_MP4_PFX " dev goip0" },
    { .description = "rtnh_len one less than struct rtnexthop (negative)", .base = NL_MP4,
      .nh = { { .len = sizeof(struct rtnexthop) - 1, .ifindex = 3 } }, .payload = sizeof(struct rtnexthop),
      .expected = "none" },
    { .description = "rtnh_len of 0 (negative)", .base = NL_MP4,
      .nh = { { .len = NL_NH_ZERO, .ifindex = 3 } },
      .expected = "none" },
    { .description = "rtnh_len longer than the payload (negative)", .base = NL_MP4,
      .nh = { { .len = 64, .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) } },
      .expected = "none" },
    { .description = "trailing bytes after the last next hop (negative)", .base = NL_MP4,
      .nh = { { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) } }, .payload = 16 + 4,
      .expected = "none" },

    /* IPv6 */
    { .description = "IPv6 two next hops as captured, sorted (positive)", .base = NL_MP6,
      .nh = { { .hops = 0, .ifindex = 3, .attr = NL_GW6(nl_test_gw6_a) },
	      { .hops = 2, .ifindex = 3, .attr = NL_GW6(nl_test_gw6_b) } },
      .expected = NL_MP6_PFX " via 2001:db8::3 dev goip0 weight 3 via 2001:db8::2 dev goip0 weight 1" },
    { .description = "IPv6 link-local gateway (positive)", .base = NL_MP6,
      .nh = { { .ifindex = 3, .attr = NL_GW6(nl_test_gw6_ll) } },
      .expected = NL_MP6_PFX " via fe80::1 dev goip0" },
    { .description = "IPv6 route with a 4-byte gateway (negative)", .base = NL_MP6,
      .nh = { { .ifindex = 3, .attr = NL_GW4(nl_test_gw4_a) } },
      .expected = "none" },
  };

  struct nl_test_capture routes;
  nl_test_route_setup();
  nl_test_load(&routes, "route-dump.pcap");

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    byte buf[128];
    int len = nl_test_multipath(buf, sizeof(buf), cases[i].nh, ARRAY_SIZE(cases[i].nh));

    if (cases[i].payload)
      len = (cases[i].payload == NL_NH_ZERO) ? 0 : cases[i].payload;

    struct nl_test_attr mp = { RTA_MULTIPATH, len, buf };
    struct nlmsghdr *h = nl_test_copy(nl_test_find_route(&routes, cases[i].base), sizeof(struct rtmsg), &mp);

    nl_test_parse_route(h, 1);
    nl_test_check_routes(cases[i].description, cases[i].expected);
    xfree(h);
  }

  nl_test_free(&routes);

  return 1;
}


#ifdef HAVE_MPLS_KERNEL

/*
 *	MPLS
 */

/* The MPLS captures come from xtcp2's brmpls rows, each a namespace with
 * a dummy interface d0 (192.0.2.1/24, 2001:db8::1/64). Every row read
 * back its namespace's links and addresses after its command. */
#define NL_TEST_MPLS_CONFIG						\
  "router id 192.0.2.1;\n"						\
  "mpls domain mdom;\n"							\
  "mpls table mtab;\n"							\
  "protocol device { scan time 86400; }\n"				\
  "protocol kernel k4 { ipv4 { import all; }; learn all; scan time 86400; }\n" \
  "protocol kernel k6 { ipv6 { import all; }; learn all; scan time 86400; }\n" \
  "protocol kernel km { mpls { table mtab; import all; }; learn all; scan time 86400; }\n"

#define NL_TEST_BRMPLS "brmpls/"

/* The links and addresses of a brmpls row's namespace */
static void
nl_test_load_ns(const char *row)
{
  struct nl_test_capture links, addrs;
  char name[128];

  bsnprintf(name, sizeof(name), NL_TEST_BRMPLS "%s/netlink_route_getlink.pcap", row);
  nl_test_load(&links, name);
  for (uint i = 0; i < links.count; i++)
    if (links.msg[i]->nlmsg_type == RTM_NEWLINK)
      nl_parse_link(links.msg[i], 0);

  bsnprintf(name, sizeof(name), NL_TEST_BRMPLS "%s/netlink_route_getaddr.pcap", row);
  nl_test_load(&addrs, name);
  for (uint i = 0; i < addrs.count; i++)
    if (addrs.msg[i]->nlmsg_type == RTM_NEWADDR)
      nl_parse_addr(addrs.msg[i], 0);

  nl_test_free(&links);
  nl_test_free(&addrs);
}

static void
nl_test_mpls_setup(void)
{
  bt_assert_msg(bt_config_parse(NL_TEST_MPLS_CONFIG), "MPLS test config");
  nl_test_pump();
}

/* The routes of the MPLS captures, as `ip route show` printed them */
static int
t_parse_mpls_capture(void)
{
  static const struct {
    const char *description;
    const char *row;		/* brmpls row, see README */
    const char *capture;
    const char *key;		/* See nl_test_route_key() */
    const char *expected;
  } cases[] = {
    { "100 as to 200/300 via inet 192.0.2.10 dev d0",
      "mpls_route_show", "ip.pcap", "table 254 100",
      "km scan 100 alien proto 3 metric 0 unicast via 192.0.2.10 dev d0 labels 200/300" },
    { "101 via inet 192.0.2.10 dev d0",
      "mpls_route_show", "ip.pcap", "table 254 101",
      "km scan 101 alien proto 3 metric 0 unicast via 192.0.2.10 dev d0" },
    { "102 nexthop as to 201 via inet 192.0.2.10 dev d0 nexthop as to 202 via inet 192.0.2.11 dev d0",
      "mpls_route_show", "ip.pcap", "table 254 102",
      "km scan 102 alien proto 3 metric 0 unicast via 192.0.2.10 dev d0 labels 201 weight 1 via 192.0.2.11 dev d0 labels 202 weight 1" },
    { "103 as to 203 via inet6 2001:db8::10 dev d0",
      "mpls_route_add_via6", "netlink_route_getroute_mpls.pcap", "table 254 103",
      "km scan 103 alien proto 3 metric 0 unicast via 2001:db8::10 dev d0 labels 203" },
    { "192.0.2.0/24 proto kernel scope link src 192.0.2.1",
      "route_encap_show", "ip.pcap", "table 254 192.0.2.0/24",
      "k4 scan 192.0.2.0/24 kernel proto 2 metric 0 unicast dev d0 scope 253 prefsrc 192.0.2.1" },
    { "198.18.20.0/24 encap mpls 100/200 via 192.0.2.10",
      "route_encap_show", "ip.pcap", "table 254 198.18.20.0/24",
      "k4 scan 198.18.20.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev d0 labels 100/200" },
    { "198.18.21.0/24 nexthop encap mpls 101 via 192.0.2.10 dev d0 weight 1 nexthop encap mpls 102 via 192.0.2.11 dev d0 weight 1",
      "route_encap_show", "ip.pcap", "table 254 198.18.21.0/24",
      "k4 scan 198.18.21.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev d0 labels 101 weight 1 via 192.0.2.11 dev d0 labels 102 weight 1" },
    { "2001:db8::/64 proto kernel metric 256",
      "route_encap_show", "netlink_route_getroute6.pcap", "table 254 2001:db8::/64",
      "k6 scan 2001:db8::/64 kernel proto 2 metric 256 unicast dev d0" },
    { "2001:db8:20::/64 encap mpls 300 via 2001:db8::10 metric 1024",
      "route_encap_show", "netlink_route_getroute6.pcap", "table 254 2001:db8:20::/64",
      "k6 scan 2001:db8:20::/64 alien proto 3 metric 1024 unicast via 2001:db8::10 dev d0 labels 300" },
  };

  nl_test_mpls_setup();

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    struct nl_test_capture routes;
    char name[128];

    bsnprintf(name, sizeof(name), NL_TEST_BRMPLS "%s/%s", cases[i].row, cases[i].capture);
    nl_test_load_ns(cases[i].row);
    nl_test_load(&routes, name);
    nl_test_parse_route(nl_test_find_route(&routes, cases[i].key), 1);
    nl_test_check_routes(cases[i].description, cases[i].expected);
    nl_test_free(&routes);
  }

  /* Every route of the dumps has a case */
  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    struct nl_test_capture routes;
    char name[128];

    if (i && !strcmp(cases[i].row, cases[i - 1].row) && !strcmp(cases[i].capture, cases[i - 1].capture))
      continue;

    bsnprintf(name, sizeof(name), NL_TEST_BRMPLS "%s/%s", cases[i].row, cases[i].capture);
    nl_test_load(&routes, name);
    for (uint j = 0; j < routes.count; j++)
    {
      char key[128];
      if (routes.msg[j]->nlmsg_type != RTM_NEWROUTE)
	continue;

      nl_test_route_key(routes.msg[j], key, sizeof(key));

      int found = 0;
      for (uint k = 0; k < ARRAY_SIZE(cases); k++)
	found |= !strcmp(cases[k].row, cases[i].row) && !strcmp(cases[k].capture, cases[i].capture) &&
	  !strcmp(cases[k].key, key);

      bt_assert_msg(found, "No case for route %s of %s", key, name);
    }
    nl_test_free(&routes);
  }

  return 1;
}

/* The notifications `ip monitor route` saw for routes added and deleted
 * with ip(8), in a namespace where d0 is at index 4, after c0 */
static int
t_parse_mpls_event(void)
{
  struct nl_test_capture events;

  nl_test_mpls_setup();
  nl_test_load_ns("mpls_event");
  nl_test_load(&events, NL_TEST_BRMPLS "mpls_event/ip.pcap");

  /* As notifications arrive, every message of the capture */
  nl_test_routes_reset();

  for (uint i = 0; i < events.count; i++)
    nl_async_msg(events.msg[i]);

  nl_test_check_routes("104 as to 204 and 198.18.23.0/24 encap mpls 105, each added and deleted",
			"km add 104 alien proto 3 metric 0 unicast via 192.0.2.10 dev d0 labels 204; "
			"km del 104 alien proto 3 metric 0 unicast via 192.0.2.10 dev d0 labels 204; "
			"k4 add 198.18.23.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev d0 labels 105; "
			"k4 del 198.18.23.0/24 alien proto 3 metric 0 unicast via 192.0.2.10 dev d0 labels 105");
  nl_test_free(&events);

  return 1;
}

#endif

/*
 *	Route matrix
 */

/* Kernel protocols for every table the ws rows use, both families: main
 * (254), 100, local (255), 256 and the highest table ID */
#define NL_TEST_WS_CONFIG						\
  "router id 192.0.2.10;\n"						\
  "ipv4 table t4v; ipv4 table t4l; ipv4 table t4h; ipv4 table t4m;\n"	\
  "ipv6 table t6v; ipv6 table t6l; ipv6 table t6h; ipv6 table t6m;\n"	\
  "protocol device { scan time 86400; }\n"				\
  "protocol kernel k4 { ipv4 { import all; }; learn all; scan time 86400; }\n" \
  "protocol kernel k6 { ipv6 { import all; }; learn all; scan time 86400; }\n" \
  "protocol kernel k4v { ipv4 { table t4v; import all; }; kernel table 100; learn all; scan time 86400; }\n" \
  "protocol kernel k6v { ipv6 { table t6v; import all; }; kernel table 100; learn all; scan time 86400; }\n" \
  "protocol kernel k4l { ipv4 { table t4l; import all; }; kernel table 255; learn all; scan time 86400; }\n" \
  "protocol kernel k6l { ipv6 { table t6l; import all; }; kernel table 255; learn all; scan time 86400; }\n" \
  "protocol kernel k4h { ipv4 { table t4h; import all; }; kernel table 256; learn all; scan time 86400; }\n" \
  "protocol kernel k6h { ipv6 { table t6h; import all; }; kernel table 256; learn all; scan time 86400; }\n" \
  "protocol kernel k4m { ipv4 { table t4m; import all; }; kernel table 4294967295; learn all; scan time 86400; }\n" \
  "protocol kernel k6m { ipv6 { table t6m; import all; }; kernel table 4294967295; learn all; scan time 86400; }\n"

#define NL_TEST_WS "ws/"

static const byte nl_test_ws_ip4[4] = { 192, 0, 2, 10 };
static const byte nl_test_ws_ip6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 1, [15] = 0x10 };

/*
 * The namespace of xtcp2's ws rows: lo 1, nlmon0 2 and a dummy interface d0
 * (3) with 192.0.2.10/24 and 2001:db8:1::10/64. The ws rows read back no
 * links or addresses, so these are those of the brmpls row
 * route_encap_show, whose d0 is also index 3, with d0's addresses changed.
 */
/* d0's addresses, as changed */
static struct nlmsghdr *nl_test_ws_addr[2];

static void
nl_test_ws_setup(void)
{
  struct nl_test_capture links, addrs;

  bt_assert_msg(bt_config_parse(NL_TEST_WS_CONFIG), "Route matrix config");
  nl_test_pump();

  nl_test_load(&links, "brmpls/route_encap_show/netlink_route_getlink.pcap");
  for (uint i = 0; i < links.count; i++)
    if (links.msg[i]->nlmsg_type == RTM_NEWLINK)
      nl_parse_link(links.msg[i], 0);

  nl_test_load(&addrs, "brmpls/route_encap_show/netlink_route_getaddr.pcap");
  struct nlmsghdr *a4 = nl_test_find_addr(&addrs, "192.0.2.1");
  struct nlmsghdr *a6 = nl_test_find_addr(&addrs, "2001:db8::1");

  for (uint i = 0; i < addrs.count; i++)
    if ((addrs.msg[i]->nlmsg_type == RTM_NEWADDR) && (addrs.msg[i] != a4) && (addrs.msg[i] != a6))
      nl_parse_addr(addrs.msg[i], 0);

  struct nl_test_attr local4 = { IFA_LOCAL, sizeof(nl_test_ws_ip4), nl_test_ws_ip4 };
  struct nl_test_attr addr4 = { IFA_ADDRESS, sizeof(nl_test_ws_ip4), nl_test_ws_ip4 };
  struct nl_test_attr addr6 = { IFA_ADDRESS, sizeof(nl_test_ws_ip6), nl_test_ws_ip6 };

  struct nlmsghdr *h = nl_test_copy(a4, sizeof(struct ifaddrmsg), &local4);
  nl_test_ws_addr[0] = nl_test_copy(h, sizeof(struct ifaddrmsg), &addr4);
  nl_test_ws_addr[1] = nl_test_copy(a6, sizeof(struct ifaddrmsg), &addr6);
  xfree(h);

  for (uint i = 0; i < ARRAY_SIZE(nl_test_ws_addr); i++)
    nl_parse_addr(nl_test_ws_addr[i], 0);

  nl_test_free(&links);
  nl_test_free(&addrs);
}

/* Remove d0's changed addresses, which the suites run after this one
 * without -f do not expect */
static void
nl_test_ws_cleanup(void)
{
  for (uint i = 0; i < ARRAY_SIZE(nl_test_ws_addr); i++)
  {
    nl_test_ws_addr[i]->nlmsg_type = RTM_DELADDR;
    nl_parse_addr(nl_test_ws_addr[i], 0);
    xfree(nl_test_ws_addr[i]);
  }
}

/*
 * Routes of xtcp2's pairwise ip route matrix (ws/route4 and ws/route6, see
 * README), each the route one ip command left, in the route dump read back
 * after it. The descriptions give the row, its category and the route as
 * `ip route show table all` printed it.
 */
static int
t_parse_route_matrix(void)
{
  static const struct {
    const char *description;
    const char *row;		/* ws row, see README */
    const char *key;		/* See nl_test_route_key() */
    const char *expected;
  } cases[] = {
    { "route4/ec-001 positive: 198.51.100.0/24 dev d0 scope link",
      "route4/ec-001", "table 254 198.51.100.0/24",
      "k4 scan 198.51.100.0/24 alien proto 3 metric 0 unicast dev d0 scope 253" },
    { "route4/pw-001 corner: default via 192.0.2.1 dev d0 proto static src 192.0.2.10 mtu 1280",
      "route4/pw-001", "table 254 0.0.0.0/0",
      "k4 scan 0.0.0.0/0 alien proto 4 metric 0 unicast via 192.0.2.1 dev d0 prefsrc 192.0.2.10 mtu 1280" },
    { "route4/bd-001 boundary: default dev d0 table local proto 255 scope link",
      "route4/bd-001", "table 255 0.0.0.0/0",
      "k4l scan 0.0.0.0/0 alien proto 255 metric 0 unicast dev d0 scope 253" },
    { "route4/bd-002 boundary: 128.0.0.0/1 dev d0 table 256 proto 255 scope link metric 4294967295",
      "route4/bd-002", "table 256 128.0.0.0/1",
      "k4h scan 128.0.0.0/1 alien proto 255 metric 4294967295 unicast dev d0 scope 253" },
    { "route4/bd-003 boundary: 198.51.100.6/31 dev d0 table 4294967295 proto 255 scope link",
      "route4/bd-003", "table 4294967295 198.51.100.6/31",
      "k4m scan 198.51.100.6/31 alien proto 255 metric 0 unicast dev d0 scope 253" },
    { "route4/bd-004 boundary: 198.51.100.7 dev d0 table local proto 255 scope link metric 4294967295",
      "route4/bd-004", "table 255 198.51.100.7/32",
      "k4l scan 198.51.100.7/32 alien proto 255 metric 4294967295 unicast dev d0 scope 253" },
    { "route4/ec-006 boundary: blackhole 198.51.100.7 nhid 10 via 192.0.2.1 dev d0 table 4294967295: the nexthop of a blackhole ignored",
      "route4/ec-006", "table 4294967295 198.51.100.7/32",
      "k4m scan 198.51.100.7/32 alien proto 3 metric 0 blackhole" },
    { "route4/ec-007 corner: unreachable 203.0.113.0/24",
      "route4/ec-007", "table 254 203.0.113.0/24",
      "k4 scan 203.0.113.0/24 alien proto 3 metric 0 unreachable" },
    { "route4/ec-008 positive: prohibit 198.51.100.0/24 nhid 10 via 192.0.2.1 dev d0: the nexthop of a prohibit route ignored",
      "route4/ec-008", "table 254 198.51.100.0/24",
      "k4 scan 198.51.100.0/24 alien proto 3 metric 0 prohibit" },
    { "route4/ec-009 positive: throw 198.51.100.0/24 nhid 10 via 192.0.2.1 dev d0: throw, skipped",
      "route4/ec-009", "table 254 198.51.100.0/24",
      "none" },
    { "route4/rn1-026 corner: 198.51.100.0/24 via 203.0.113.1 dev d0 onlink table 4294967295 proto 255 metric 4294967295 src 192.0.2.10 mtu 1280",
      "route4/rn1-026", "table 4294967295 198.51.100.0/24",
      "k4m scan 198.51.100.0/24 alien proto 255 metric 4294967295 unicast via 203.0.113.1 dev d0 onlink prefsrc 192.0.2.10 mtu 1280" },
    { "route4/ec-010 positive: 198.51.100.0/24 via inet6 2001:db8:1::1 dev d0",
      "route4/ec-010", "table 254 198.51.100.0/24",
      "k4 scan 198.51.100.0/24 alien proto 3 metric 0 unicast via 2001:db8:1::1 dev d0" },
    { "route4/pw-004 corner: multicast 198.51.100.6/31 table 256 src 192.0.2.10 metric 7 mtu lock 1400 nexthop via 192.0.2.1 dev d0 weight 1 nexthop via 192.0.2.2 dev d0 weight 256: multicast, skipped",
      "route4/pw-004", "table 256 multicast 198.51.100.6/31",
      "none" },
    { "route4/pw-005 corner: blackhole 198.51.100.7 nhid 10 via 192.0.2.1 dev d0 table 4294967295 proto static scope link src 192.0.2.10 mtu lock 1400",
      "route4/pw-005", "table 4294967295 198.51.100.7/32",
      "k4m scan 198.51.100.7/32 alien proto 4 metric 0 blackhole scope 253 prefsrc 192.0.2.10 lock 4 mtu 1400" },
    { "route4/pw-006 corner: unreachable 203.0.113.0/24 proto 255 src 192.0.2.10 advmss 1300",
      "route4/pw-006", "table 254 203.0.113.0/24",
      "k4 scan 203.0.113.0/24 alien proto 255 metric 0 unreachable prefsrc 192.0.2.10 advmss 1300" },
    { "route4/pw-007 boundary: 198.51.100.0/24 via inet6 2001:db8:1::1 dev d0 table 100 scope link src 192.0.2.10 metric 4294967295 mtu 1280",
      "route4/pw-007", "table 100 198.51.100.0/24",
      "k4v scan 198.51.100.0/24 alien proto 3 metric 4294967295 unicast via 2001:db8:1::1 dev d0 scope 253 prefsrc 192.0.2.10 mtu 1280" },
    { "route4/pw-011 corner: blackhole 198.51.100.6/31 nhid 10 via 192.0.2.1 dev d0 proto unspec mtu 1280: proto unspec, skipped",
      "route4/pw-011", "table 254 198.51.100.6/31",
      "none" },
    { "route4/pw-013 corner: prohibit 203.0.113.0/24 table 256 scope host advmss 1300",
      "route4/pw-013", "table 256 203.0.113.0/24",
      "k4h scan 203.0.113.0/24 alien proto 3 metric 0 prohibit scope 254 advmss 1300" },
    { "route4/pw-014 boundary: local 198.51.100.0/24 dev d0 table local scope host mtu 1280: local, skipped",
      "route4/pw-014", "table 255 local 198.51.100.0/24",
      "none" },
    { "route4/pw-017 corner: 128.0.0.0/1 proto static metric 7 mtu lock 1400 nexthop via 192.0.2.1 dev d0 weight 1 nexthop via 192.0.2.2 dev d0 weight 256",
      "route4/pw-017", "table 254 128.0.0.0/1",
      "k4 scan 128.0.0.0/1 alien proto 4 metric 7 unicast via 192.0.2.2 dev d0 weight 256 via 192.0.2.1 dev d0 weight 1 lock 4 mtu 1400" },
    { "route4/pw-022 corner: local default dev d0 table local proto static scope host src 192.0.2.10 metric 4294967295 mtu 1280: local, skipped",
      "route4/pw-022", "table 255 local 0.0.0.0/0",
      "none" },
    { "route4/pw-023 boundary: default nhid 10 via 192.0.2.1 dev d0 table local proto 255",
      "route4/pw-023", "table 255 0.0.0.0/0",
      "k4l scan 0.0.0.0/0 alien proto 255 metric 0 unicast via 192.0.2.1 dev d0" },
    { "route4/pw-024 corner: 128.0.0.0/1 via inet6 2001:db8:1::1 dev d0 table 100 proto unspec mtu lock 1400: proto unspec, skipped",
      "route4/pw-024", "table 100 128.0.0.0/1",
      "none" },
    { "route4/pw-038 corner: throw default table 4294967295 scope host src 192.0.2.10 metric 7 mtu 1280: throw, skipped",
      "route4/pw-038", "table 4294967295 0.0.0.0/0",
      "none" },
    { "route4/pw-046 corner: default dev d0 proto unspec scope link metric 1024 mtu lock 1400: proto unspec, skipped",
      "route4/pw-046", "table 254 0.0.0.0/0",
      "none" },
    { "route4/pw-047 boundary: multicast 128.0.0.0/1 via 192.0.2.1 dev d0 table 256 metric 4294967295 mtu 1280: multicast, skipped",
      "route4/pw-047", "table 256 multicast 128.0.0.0/1",
      "none" },
    { "route4/pw-057 boundary: 198.51.100.6/31 via 192.0.2.1 dev d0 table local metric 4294967295",
      "route4/pw-057", "table 255 198.51.100.6/31",
      "k4l scan 198.51.100.6/31 alien proto 3 metric 4294967295 unicast via 192.0.2.1 dev d0" },
    { "route4/pw-061 corner: broadcast 198.51.100.7 dev d0 table 256 scope link mtu lock 1400: broadcast, skipped",
      "route4/pw-061", "table 256 broadcast 198.51.100.7/32",
      "none" },
    { "route4/pw-064 corner: 203.0.113.0/24 via 192.0.2.1 dev d0 table local",
      "route4/pw-064", "table 255 203.0.113.0/24",
      "k4l scan 203.0.113.0/24 alien proto 3 metric 0 unicast via 192.0.2.1 dev d0" },
    { "route4/pw-068 corner: default table local advmss 1300 nexthop via 192.0.2.1 dev d0 weight 1 nexthop via 192.0.2.2 dev d0 weight 256",
      "route4/pw-068", "table 255 0.0.0.0/0",
      "k4l scan 0.0.0.0/0 alien proto 3 metric 0 unicast via 192.0.2.2 dev d0 weight 256 via 192.0.2.1 dev d0 weight 1 advmss 1300" },
    { "route6/ec-001 positive: 2001:db8:2::/64 dev d0 metric 1024 pref medium",
      "route6/ec-001", "table 254 2001:db8:2::/64",
      "k6 scan 2001:db8:2::/64 alien proto 3 metric 1024 unicast dev d0" },
    { "route6/pw-001 corner: default via 2001:db8:1::1 dev d0 proto static src 2001:db8:1::10 metric 1024 expires 59sec mtu 1280 pref low: metric 0, which the kernel keeps as 1024 for IPv6",
      "route6/pw-001", "table 254 ::/0",
      "k6 scan ::/0 alien proto 4 metric 1024 unicast via 2001:db8:1::1 dev d0 prefsrc 2001:db8:1::10 mtu 1280" },
    { "route6/bd-001 boundary: default dev d0 table local proto 255 metric 1024 pref medium: metric 0, which the kernel keeps as 1024 for IPv6",
      "route6/bd-001", "table 255 ::/0",
      "k6l scan ::/0 alien proto 255 metric 1024 unicast dev d0" },
    { "route6/bd-002 boundary: 8000::/1 dev d0 table 256 proto 255 metric 4294967295 pref medium",
      "route6/bd-002", "table 256 8000::/1",
      "k6h scan 8000::/1 alien proto 255 metric 4294967295 unicast dev d0" },
    { "route6/bd-003 boundary: 2001:db8:2::/127 dev d0 table 4294967295 proto 255 metric 1024 pref medium: metric 0, which the kernel keeps as 1024 for IPv6",
      "route6/bd-003", "table 4294967295 2001:db8:2::/127",
      "k6m scan 2001:db8:2::/127 alien proto 255 metric 1024 unicast dev d0" },
    { "route6/bd-004 boundary: 2001:db8:2::7 dev d0 table local proto 255 metric 4294967295 pref medium",
      "route6/bd-004", "table 255 2001:db8:2::7/128",
      "k6l scan 2001:db8:2::7/128 alien proto 255 metric 4294967295 unicast dev d0" },
    { "route6/ec-003 corner: local default via 2001:db8:1::1 dev d0 table 100 proto 255 metric 1024 mtu lock 1400 pref medium: local, skipped",
      "route6/ec-003", "table 100 local ::/0",
      "none" },
    { "route6/ec-004 corner: anycast 8000::/1 via 2001:db8:3::1 dev d0 table local metric 4294967295 onlink advmss 1300 pref high: anycast, skipped",
      "route6/ec-004", "table 255 8000::/1",
      "none" },
    { "route6/ec-006 boundary: blackhole 2001:db8:2::7 nhid 10 via 2001:db8:1::1 dev d0 table 4294967295 metric 1024 pref medium: the nexthop of a blackhole ignored",
      "route6/ec-006", "table 4294967295 2001:db8:2::7/128",
      "k6m scan 2001:db8:2::7/128 alien proto 3 metric 1024 blackhole" },
    { "route6/ec-007 corner: unreachable ::ffff:198.51.100.0/120 dev lo metric 1024 pref medium: dev lo ignored",
      "route6/ec-007", "table 254 ::ffff:198.51.100.0/120",
      "k6 scan ::ffff:198.51.100.0/120 alien proto 3 metric 1024 unreachable" },
    { "route6/ec-008 positive: prohibit 2001:db8:2::/64 dev lo metric 1024 pref medium: dev lo ignored",
      "route6/ec-008", "table 254 2001:db8:2::/64",
      "k6 scan 2001:db8:2::/64 alien proto 3 metric 1024 prohibit" },
    { "route6/ec-009 positive: throw 2001:db8:2::/64 dev lo metric 1024 pref medium: throw, skipped",
      "route6/ec-009", "table 254 2001:db8:2::/64",
      "none" },
    { "route6/pw-004 corner: multicast 2001:db8:2::/127 table 256 metric 7 mtu 1280 pref low nexthop via 2001:db8:1::1 dev d0 weight 1 nexthop via 2001:db8:1::2 dev d0 weight 256: multicast, skipped",
      "route6/pw-004", "table 256 multicast 2001:db8:2::/127",
      "none" },
    { "route6/pw-008 corner: default table local proto static src 2001:db8:1::10 metric 1024 expires 59sec pref medium nexthop via 2001:db8:1::1 dev d0 weight 1 nexthop via 2001:db8:1::2 dev d0 weight 256",
      "route6/pw-008", "table 255 ::/0",
      "k6l scan ::/0 alien proto 4 metric 1024 unicast via 2001:db8:1::2 dev d0 weight 256 via 2001:db8:1::1 dev d0 weight 1 prefsrc 2001:db8:1::10" },
    { "route6/pw-012 corner: multicast 2001:db8:2::7 dev d0 src 2001:db8:1::10 metric 1024 advmss 1300 pref low: multicast, skipped",
      "route6/pw-012", "table 254 multicast 2001:db8:2::7/128",
      "none" },
    { "route6/pw-016 boundary: default via 2001:db8:1::1 dev d0 proto 255 src 2001:db8:1::10 metric 4294967295 advmss 1300 pref medium",
      "route6/pw-016", "table 254 ::/0",
      "k6 scan ::/0 alien proto 255 metric 4294967295 unicast via 2001:db8:1::1 dev d0 prefsrc 2001:db8:1::10 advmss 1300" },
    { "route6/pw-017 corner: 8000::/1 dev d0 proto static src 2001:db8:1::10 metric 7 expires 59sec pref medium",
      "route6/pw-017", "table 254 8000::/1",
      "k6 scan 8000::/1 alien proto 4 metric 7 unicast dev d0 prefsrc 2001:db8:1::10" },
    { "route6/pw-020 corner: multicast ::ffff:198.51.100.0/120 nhid 10 via 2001:db8:1::1 dev d0 proto static metric 1024 expires 59sec mtu lock 1400 pref high: multicast, skipped",
      "route6/pw-020", "table 254 multicast ::ffff:198.51.100.0/120",
      "none" },
    { "route6/pw-024 corner: 8000::/1 via 2001:db8:1::1 dev d0 table 100 metric 1024 pref low: proto 0, which the kernel keeps as boot (3) for IPv6",
      "route6/pw-024", "table 100 8000::/1",
      "k6v scan 8000::/1 alien proto 3 metric 1024 unicast via 2001:db8:1::1 dev d0" },
    { "route6/pw-041 corner: multicast default dev d0 metric 1024 advmss 1300 pref medium: multicast, skipped",
      "route6/pw-041", "table 254 multicast ::/0",
      "none" },
    { "route6/pw-057 boundary: 2001:db8:2::7 via 2001:db8:3::1 dev d0 metric 1024 onlink mtu 1280 pref medium",
      "route6/pw-057", "table 254 2001:db8:2::7/128",
      "k6 scan 2001:db8:2::7/128 alien proto 3 metric 1024 unicast via 2001:db8:3::1 dev d0 onlink mtu 1280" },
    { "route6/pw-061 corner: ::ffff:198.51.100.0/120 via 2001:db8:1::1 dev d0 table 100 metric 4294967295 mtu lock 1400 pref medium",
      "route6/pw-061", "table 100 ::ffff:198.51.100.0/120",
      "k6v scan ::ffff:198.51.100.0/120 alien proto 3 metric 4294967295 unicast via 2001:db8:1::1 dev d0 lock 4 mtu 1400" },
    { "route6/pw-062 corner: ::ffff:198.51.100.0/120 dev d0 table local metric 1024 pref medium",
      "route6/pw-062", "table 255 ::ffff:198.51.100.0/120",
      "k6l scan ::ffff:198.51.100.0/120 alien proto 3 metric 1024 unicast dev d0" },
    { "route6/pw-065 corner: default via 2001:db8:3::1 dev d0 metric 7 onlink pref medium",
      "route6/pw-065", "table 254 ::/0",
      "k6 scan ::/0 alien proto 3 metric 7 unicast via 2001:db8:3::1 dev d0 onlink" },
    { "route6/pw-067 boundary: default nhid 10 via 2001:db8:1::1 dev d0 table 4294967295 proto 255 metric 1024 pref medium",
      "route6/pw-067", "table 4294967295 ::/0",
      "k6m scan ::/0 alien proto 255 metric 1024 unicast via 2001:db8:1::1 dev d0" },
    { "route6/pw-069 boundary: 8000::/1 metric 1024 advmss 1300 pref high nexthop via 2001:db8:1::1 dev d0 weight 1 nexthop via 2001:db8:1::2 dev d0 weight 256",
      "route6/pw-069", "table 254 8000::/1",
      "k6 scan 8000::/1 alien proto 3 metric 1024 unicast via 2001:db8:1::2 dev d0 weight 256 via 2001:db8:1::1 dev d0 weight 1 advmss 1300" },
    { "route6/pw-071 boundary: 2001:db8:2::7 metric 1024 pref medium nexthop via 2001:db8:1::1 dev d0 weight 1 nexthop via 2001:db8:1::2 dev d0 weight 256",
      "route6/pw-071", "table 254 2001:db8:2::7/128",
      "k6 scan 2001:db8:2::7/128 alien proto 3 metric 1024 unicast via 2001:db8:1::2 dev d0 weight 256 via 2001:db8:1::1 dev d0 weight 1" },
    { "route6/pw-072 boundary: 2001:db8:2::/64 dev d0 table 256 metric 1024 pref medium",
      "route6/pw-072", "table 256 2001:db8:2::/64",
      "k6h scan 2001:db8:2::/64 alien proto 3 metric 1024 unicast dev d0" },
    { "route6/rn1-003 boundary: 2001:db8:2::/64 via 2001:db8:1::1 dev d0 proto 255 metric 1024 pref low",
      "route6/rn1-003", "table 254 2001:db8:2::/64",
      "k6 scan 2001:db8:2::/64 alien proto 255 metric 1024 unicast via 2001:db8:1::1 dev d0" },
    { "route6/rn1-009 corner: 2001:db8:2::/64 nhid 10 via 2001:db8:1::1 dev d0 src 2001:db8:1::10 metric 4294967295 expires 59sec pref medium: proto 0, which the kernel keeps as boot (3) for IPv6",
      "route6/rn1-009", "table 254 2001:db8:2::/64",
      "k6 scan 2001:db8:2::/64 alien proto 3 metric 4294967295 unicast via 2001:db8:1::1 dev d0 prefsrc 2001:db8:1::10" },
    { "route6/rn1-015 corner: default via 2001:db8:1::1 dev d0 table 256 src 2001:db8:1::10 metric 1024 pref medium: proto 0, which the kernel keeps as boot (3) for IPv6",
      "route6/rn1-015", "table 256 ::/0",
      "k6h scan ::/0 alien proto 3 metric 1024 unicast via 2001:db8:1::1 dev d0 prefsrc 2001:db8:1::10" },
    { "route6/rn1-022 corner: 2001:db8:2::/127 proto 255 metric 1024 mtu 1280 pref medium nexthop via 2001:db8:1::1 dev d0 weight 1 nexthop via 2001:db8:1::2 dev d0 weight 256",
      "route6/rn1-022", "table 254 2001:db8:2::/127",
      "k6 scan 2001:db8:2::/127 alien proto 255 metric 1024 unicast via 2001:db8:1::2 dev d0 weight 256 via 2001:db8:1::1 dev d0 weight 1 mtu 1280" },
  };

  nl_test_ws_setup();

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    struct nl_test_capture routes;
    char name[128];

    bsnprintf(name, sizeof(name), NL_TEST_WS "%s/netlink_route_dump.pcap", cases[i].row);
    nl_test_load(&routes, name);
    nl_test_parse_route(nl_test_find_route(&routes, cases[i].key), 1);
    nl_test_check_routes(cases[i].description, cases[i].expected);
    nl_test_free(&routes);
  }

  nl_test_ws_cleanup();

  return 1;
}

/*
 * The kernel's answers to "ip route get" in xtcp2's ws rows (see README),
 * from each row's ip.pcap: the route, and the links ip asked for to print
 * it. A lookup answers with a clone of the route (RTM_F_CLONED), which
 * BIRD ignores; with fibmatch, with the FIB entry itself. ip asks for the
 * links' names only, so the kernel's link messages have their header (its
 * flags) and IFLA_IFNAME, which BIRD takes as malformed. The test adds an
 * IFLA_MTU of 1500 to each, parses them first, and deletes them again
 * afterwards.
 */
static int
t_parse_route_get(void)
{
  static const struct {
    const char *description;
    const char *row;		/* ws row, see README */
    const char *key;		/* See nl_test_route_key() */
    const char *expected;
    const char *name;		/* A link to check, or NULL */
    const char *link;
  } cases[] = {
    { "routeget4/pw-003 negative: ip -4 route get 198.51.100.7 from 192.0.2.10 mark 4294967295 ipproto icmp sport 1234 dport 443 tos 0x10 notify: a clone, ignored",
      "routeget4/pw-003", "table 254 198.51.100.7/32", "none" },
    { "routeget6/bd-001 negative: ip -6 route get 2001:db8:1::5/128 mark 0 uid 0 dport 65535 flowlabel 0xfffff: a clone, ignored",
      "routeget6/bd-001", "table 254 2001:db8:1::5/128", "none" },
    { "fibt/fib_carrier_test-017 positive: ip route get fibmatch 198.51.100.2: 198.51.100.0/24 dev dummy0 proto kernel scope link src 198.51.100.1, dummy0 up without carrier",
      "fibt/fib_carrier_test-017", "table 254 198.51.100.0/24",
      "k4 scan 198.51.100.0/24 kernel proto 2 metric 0 unicast dev dummy0 scope 253 prefsrc 198.51.100.1",
      "dummy0", "dummy0 index 4 mtu 1500 admin-up multiaccess broadcast multicast" },
    { "fibt/fib_down_test-011 corner: ip route get fibmatch 203.0.113.1 oif dummy1: nexthop via 198.51.100.2 dev dummy0 dead linkdown, nexthop via 192.0.2.2 dev dummy1; the links have no addresses here, so the next hops are strange",
      "fibt/fib_down_test-011", "table 254 203.0.113.0/24", "none",
      "dummy0", "dummy0 index 4 mtu 1500 multiaccess broadcast multicast" },
    { "fibt/fib_down_test-012 corner: ip -6 route get fibmatch 2001:db8:3::1 oif dummy1: nexthop via 2001:db8:2::2 dev dummy1, nexthop via 2001:db8:1::2 dev dummy0 dead linkdown; strange next hops, as above",
      "fibt/fib_down_test-012", "table 254 2001:db8:3::/64", "none" },
    { "fibt/ipv4_route_test-083 negative: ip route get fibmatch 172.16.102.1 dsfield 0x10: 172.16.102.0/24 tos 0x10 via 172.16.103.2 dev veth3, TOS skipped",
      "fibt/ipv4_route_test-083", "table 254 172.16.102.0/24", "none" },
  };

  static const u32 mtu1500 = 1500;
  struct nl_test_attr mtu = { IFLA_MTU, sizeof(mtu1500), &mtu1500 };

  bt_assert_msg(bt_config_parse(NL_TEST_WS_CONFIG), "Route get config");
  nl_test_pump();

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    struct nl_test_capture c;
    char name[128];

    bsnprintf(name, sizeof(name), NL_TEST_WS "%s/ip.pcap", cases[i].row);
    nl_test_load(&c, name);

    struct nlmsghdr *links[8];
    uint n = 0;
    for (uint j = 0; j < c.count; j++)
      if ((c.msg[j]->nlmsg_type == RTM_NEWLINK) && (n < ARRAY_SIZE(links)))
      {
	links[n] = nl_test_copy(c.msg[j], sizeof(struct ifinfomsg), &mtu);
	nl_parse_link(links[n++], 0);
      }

    nl_test_parse_route(nl_test_find_route(&c, cases[i].key), 1);
    nl_test_check_routes(cases[i].description, cases[i].expected);

    if (cases[i].name)
      nl_test_check_iface(cases[i].description, if_find_by_name(cases[i].name), cases[i].link);

    while (n--)
    {
      links[n]->nlmsg_type = RTM_DELLINK;
      nl_parse_link(links[n], 0);
      xfree(links[n]);
    }

    nl_test_free(&c);
  }

  return 1;
}

/*
 *	Notifications
 */

#define NL_TEST_MONITOR_CONFIG						\
  "router id 192.0.2.10;\n"						\
  "ipv4 table t4l; ipv6 table t6l;\n"					\
  "protocol device { scan time 86400; }\n"				\
  "protocol kernel k4 { ipv4 { import all; }; learn all; scan time 86400; }\n" \
  "protocol kernel k6 { ipv6 { import all; }; learn all; scan time 86400; }\n" \
  "protocol kernel k4l { ipv4 { table t4l; import all; }; kernel table 255; learn all; scan time 86400; }\n" \
  "protocol kernel k6l { ipv6 { table t6l; import all; }; kernel table 255; learn all; scan time 86400; }\n"

/*
 * xtcp2's link-write rtnl/monitor_all row (see README): "ip monitor all"
 * while ip(8) changed links and added addresses, routes and more. The
 * capture starts with ip's own link dump (lo, nlmon0, c0 3, d0 4, r0p 5 and
 * r0 6), which asked for names only, so BIRD takes each link as malformed
 * and knows none of them. Then the notifications, which have sequence
 * number 0 (the rest are replies to ip's requests), go through
 * nl_async_msg() as they arrived:
 *
 *   inet 224.0.0.250/32 autojoin dev c0, its local route
 *   d0 up (a full link message), multicast ff00::/8 dev d0 table local
 *   2001:db8:1::/64 dev d0 proto kernel, inet6 2001:db8:1::1/64 nodad dev
 *     d0, its local and anycast routes
 *   netconf, rule, nexthop, stats, nsid (ignored)
 *   2001:db8:5::/64 dev r0 proto kernel expires 600, from a router advert
 */
static int
t_parse_monitor(void)
{
  static const struct {
    const char *description;
    const char *name;		/* Interface, NULL for the routes */
    int addrs;			/* Its addresses rather than itself */
    const char *expected;
  } cases[] = {
    { "c0, only in the dump of names, malformed (negative)", "c0", 0,
      "none" },
    { "c0 224.0.0.250/32 autojoin, for an interface BIRD does not know (negative)", "c0", 1,
      "none" },
    { "r0, only in the dump of names, malformed (negative)", "r0", 0,
      "none" },
    { "d0, created by its notification when set up (positive)", "d0", 0,
      "d0 index 4 mtu 1500 admin-up link-up multiaccess broadcast multicast lladdr ee:fb:d3:3c:22:c8" },
    { "d0 2001:db8:1::1/64 nodad, by notification (positive)", "d0", 1,
      "2001:db8:1::1 net 2001:db8:1::/64 scope univ primary" },
    { "routes: 2001:db8:1::/64 learned; local, multicast and anycast ones skipped; "
      "2001:db8:5::/64 of the unknown r0 dropped", NULL, 0,
      "k6 add 2001:db8:1::/64 kernel proto 2 metric 256 unicast dev d0" },
  };

  struct nl_test_capture c;

  bt_assert_msg(bt_config_parse(NL_TEST_MONITOR_CONFIG), "Monitor test config");
  nl_test_pump();
  nl_test_load(&c, "rtnl/monitor_all/ip.pcap");

  /* The dump, up to its NLMSG_DONE */
  uint n = 0;
  for (; (n < c.count) && (c.msg[n]->nlmsg_type != NLMSG_DONE); n++)
    nl_parse_link(c.msg[n], 0);

  nl_test_routes_reset();
  for (uint i = n; i < c.count; i++)
    if (!c.msg[i]->nlmsg_seq)
      nl_async_msg(c.msg[i]);

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    struct iface *ifi = cases[i].name ? if_find_by_name(cases[i].name) : NULL;

    if (!cases[i].name)
      nl_test_check_routes(cases[i].description, cases[i].expected);
    else if (cases[i].addrs)
      nl_test_check_addrs(cases[i].description, ifi, cases[i].expected);
    else
      nl_test_check_iface(cases[i].description, ifi, cases[i].expected);
  }

  /* Gone again, for the next suites' links of the same names */
  for (uint i = c.count; i--; )
    if (!c.msg[i]->nlmsg_seq && (c.msg[i]->nlmsg_type == RTM_NEWADDR))
    {
      c.msg[i]->nlmsg_type = RTM_DELADDR;
      nl_parse_addr(c.msg[i], 0);
    }

  for (uint i = 0; i < n; i++)
  {
    c.msg[i]->nlmsg_type = RTM_DELLINK;
    nl_parse_link(c.msg[i], 0);
  }

  nl_test_free(&c);

  return 1;
}


/*
 *	Errors
 */

/* nl_error() logs what the kernel refused with; record it instead */
static char nl_test_log[256];

void
nl_test_log_rl(struct tbf *rl UNUSED, const char *msg, ...)
{
  va_list args;
  va_start(args, msg);

  /* Skip the log class */
  if ((msg[0] > 0) && (msg[0] < ' '))
    msg++;

  bvsnprintf(nl_test_log, sizeof(nl_test_log), msg, args);
  va_end(args);
}

/* The kernel's answer to the request of a ws row: its last NLMSG_ERROR */
static struct nlmsghdr *
nl_test_find_error(struct nl_test_capture *c)
{
  for (int i = c->count - 1; i >= 0; i--)
    if (c->msg[i]->nlmsg_type == NLMSG_ERROR)
      return c->msg[i];

  bt_abort_msg("No error message in the capture");
  return NULL;
}

static const char *
nl_test_errno_name(int err)
{
  switch (err)
  {
  case 0:		return "0";
  case ENOENT:		return "ENOENT";
  case ESRCH:		return "ESRCH";
  case ENOBUFS:		return "ENOBUFS";
  case EEXIST:		return "EEXIST";
  case ENODEV:		return "ENODEV";
  case EINVAL:		return "EINVAL";
  case ENETUNREACH:	return "ENETUNREACH";
  case EHOSTUNREACH:	return "EHOSTUNREACH";
  default:		return "?";
  }
}

#define NL_ERR_ONLY_HEADER	1	/* Cut after struct nlmsgerr's own header */
#define NL_ERR_SHORT		2	/* Cut before the end of struct nlmsgerr */

/*
 * The kernel's answers to the ip commands of xtcp2's ws rows (see README),
 * from each row's ip.pcap: an acknowledgement, or an error with the request
 * and, from the extended ACK, a message, as ip printed it. The kernel sends
 * NLM_F_ACK_TLVS with the full request, as ip does not ask for capped
 * acknowledgements. The cut rows are shortened copies, which the kernel
 * never sends.
 */
static int
t_parse_error(void)
{
  static const struct {
    const char *description;
    const char *row;		/* ws row, see README */
    int ignore_esrch;
    int cut;
    const char *expected;	/* errno, then what was logged */
  } cases[] = {
    /* Acknowledgements */
    { "route4/ec-001 positive: ip -4 route add 198.51.100.0/24 dev d0, acknowledged",
      "route4/ec-001", 0, 0, "0 none" },
    { "route6/ec-001 positive: ip -6 route add 2001:db8:2::/64 dev d0, acknowledged",
      "route6/ec-001", 0, 0, "0 none" },

    /* Errors with a message */
    { "route4/ec-005 negative: ip -4 route del ... table 256: Error: FIB table does not exist.",
      "route4/ec-005", 0, 0, "ESRCH Netlink: FIB table does not exist" },
    { "route4/ec-005 with ESRCH ignored: a delete from a table that is gone is not logged (corner)",
      "route4/ec-005", 1, 0, "ESRCH none" },
    { "route6/gone-1 negative: ip -6 route del ... table 256: Error: FIB table does not exist.",
      "route6/gone-1", 0, 0, "ESRCH Netlink: FIB table does not exist" },
    { "route4/ng-001 negative: ip -4 route add blackhole 198.51.100.0/24 dev d0: Error: Gateway, device and multipath can not be specified for this route type.",
      "route4/ng-001", 0, 0, "EINVAL Netlink: Gateway, device and multipath can not be specified for this route type" },
    { "route4/ng-038 negative: ip -4 route add 198.51.100.1/24 dev d0: Error: Invalid prefix for given prefix length.",
      "route4/ng-038", 0, 0, "EINVAL Netlink: Invalid prefix for given prefix length" },
    { "route4/ng-030 negative: ip -4 route add local 198.51.100.0/24 scope global dev d0: Error: Invalid scope.",
      "route4/ng-030", 0, 0, "EINVAL Netlink: Invalid scope" },
    { "route4/pw-016 negative: ip -4 route append 0.0.0.0/0 ... scope link ... via 192.0.2.1: Error: Nexthop has invalid gateway.",
      "route4/pw-016", 0, 0, "ENETUNREACH Netlink: Nexthop has invalid gateway" },
    { "route4/ec-004 negative: ip -4 route prepend broadcast 128.0.0.0/1 ... via 203.0.113.1 dev d0 onlink: Error: Nexthop has invalid scope.",
      "route4/ec-004", 0, 0, "EINVAL Netlink: Nexthop has invalid scope" },
    { "route4/ec-003 negative: ip -4 route append local 0.0.0.0/0 ... scope host ... via 192.0.2.1 dev d0: Error: Route with host scope can not have a gateway.",
      "route4/ec-003", 0, 0, "EINVAL Netlink: Route with host scope can not have a gateway" },
    { "route4/pw-010 negative: ip -4 route replace local 128.0.0.0/1 ... scope host ... nexthop ... nexthop ...: Error: Route with host scope can not have multiple nexthops.",
      "route4/pw-010", 0, 0, "EINVAL Netlink: Route with host scope can not have multiple nexthops" },
    { "route6/ng-014 negative: ip -6 route add 2001:db8:2::/64 via inet 192.0.2.1 dev d0: Error: IPv6 does not support RTA_VIA attribute.",
      "route6/ng-014", 0, 0, "EINVAL Netlink: IPv6 does not support RTA_VIA attribute" },

    /* Errors without a message */
    { "route4/dup-1 negative: ip -4 route add 198.51.100.0/24 dev d0 again: RTNETLINK answers: File exists",
      "route4/dup-1", 0, 0, "EEXIST Netlink: File exists" },
    { "route6/dup-1 negative: ip -6 route add 2001:db8:2::/64 dev d0 again: RTNETLINK answers: File exists",
      "route6/dup-1", 0, 0, "EEXIST Netlink: File exists" },
    { "route4/ng-025 negative: ip -4 route add 198.51.100.0/24, no device: RTNETLINK answers: No such device",
      "route4/ng-025", 0, 0, "ENODEV Netlink: No such device" },
    { "route6/ng-001 negative: ip -6 route add 2001:db8:2::/64, no device: RTNETLINK answers: No such device",
      "route6/ng-001", 0, 0, "ENODEV Netlink: No such device" },
    { "fibt/ipv4_route_test-054 negative: ip ro change 172.16.105.0/24 via 172.16.101.2, no such route: RTNETLINK answers: No such file or directory",
      "fibt/ipv4_route_test-054", 0, 0, "ENOENT Netlink: No such file or directory" },
    { "fibnh/ipv4_withv6_fcnal-005 negative: ip ro replace 172.16.101.1/32 via inet6 2001:db8:50::1 dev veth1, no route to the gateway: RTNETLINK answers: No route to host",
      "fibnh/ipv4_withv6_fcnal-005", 0, 0, "EHOSTUNREACH Netlink: No route to host" },
    { "fibt/ipv6_route_test-033 negative: ip -6 ro replace 2001:db8:104::/64 via 2001:db8:104::2, no route to the gateway: RTNETLINK answers: No route to host",
      "fibt/ipv6_route_test-033", 0, 0, "EHOSTUNREACH Netlink: No route to host" },
    { "route4/gone-3 negative: ip -4 route del unreachable 0.0.0.0/0 ... nhid 10, no such route: RTNETLINK answers: No such process",
      "route4/gone-3", 0, 0, "ESRCH Netlink: No such process" },
    { "route6/gone-3 negative: ip -6 route del prohibit 8000::/1 ... nhid 10, no such route: RTNETLINK answers: No such process",
      "route6/gone-3", 0, 0, "ESRCH Netlink: No such process" },
    { "route4/gone-3 with ESRCH ignored, as for deletes of routes already gone (corner)",
      "route4/gone-3", 1, 0, "ESRCH none" },
    { "route6/gone-3 with ESRCH ignored, as for deletes of routes already gone (corner)",
      "route6/gone-3", 1, 0, "ESRCH none" },
    { "route4/dup-1 with ESRCH ignored, another error still logged (corner)",
      "route4/dup-1", 1, 0, "EEXIST Netlink: File exists" },

    /* Cut short */
    { "route4/ng-030 cut after the request's header, its attributes missing though not capped (negative)",
      "route4/ng-030", 0, NL_ERR_ONLY_HEADER, "EINVAL none" },
    { "route6/ng-014 cut after the request's header, its attributes missing though not capped (negative)",
      "route6/ng-014", 0, NL_ERR_ONLY_HEADER, "EINVAL none" },
    { "route4/ng-030 cut before the end of struct nlmsgerr (negative)",
      "route4/ng-030", 0, NL_ERR_SHORT, "ENOBUFS none" },
    { "route4/ec-001 acknowledgement cut before the end of struct nlmsgerr (negative)",
      "route4/ec-001", 0, NL_ERR_SHORT, "ENOBUFS none" },
  };

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    struct nl_test_capture c;
    char name[128], got[384];

    bsnprintf(name, sizeof(name), NL_TEST_WS "%s/ip.pcap", cases[i].row);
    nl_test_load(&c, name);

    struct nlmsghdr *h = nl_test_find_error(&c);
    if (cases[i].cut == NL_ERR_ONLY_HEADER)
      h->nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
    else if (cases[i].cut == NL_ERR_SHORT)
      h->nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr)) - 1;

    bsnprintf(nl_test_log, sizeof(nl_test_log), "none");
    int err = nl_error(h, cases[i].ignore_esrch);
    bsnprintf(got, sizeof(got), "%s %s", nl_test_errno_name(err), nl_test_log);

    bt_assert_msg(!strcmp(got, cases[i].expected), "%s: got \"%s\", expected \"%s\"",
		  cases[i].description, got, cases[i].expected);
    nl_test_free(&c);
  }

  return 1;
}

#ifdef CONFIG_BRIDGE

/*
 *	Bridge FDB
 */

/* The bridge rows of xtcp2's brmpls corpus (see README) have a VLAN
 * filtering bridge br0 with one port v0, the end of a veth pair whose other
 * end v0p is outside the bridge. The protocol starts when br0 comes up. */
#define NL_TEST_BRIDGE_CONFIG						\
  "router id 192.0.2.1;\n"						\
  "eth table etab;\n"							\
  "protocol device { scan time 86400; }\n"				\
  "protocol bridge kb { eth { table etab; }; bridge device \"br0\"; vlan filtering yes; }\n"

static struct kbr_proto *
nl_test_bridge_setup(const char *row)
{
  bt_assert_msg(bt_config_parse(NL_TEST_BRIDGE_CONFIG), "Bridge test config");
  nl_test_pump();
  nl_test_load_ns(row);
  nl_test_pump();

  struct iface *br = if_find_by_name("br0");
  struct kbr_proto *p = br ? HASH_FIND(nl_bridge_map, BRH, br->index) : NULL;
  bt_assert_msg(p && (p->p.proto_state == PS_UP), "Bridge protocol up on br0");
  return p;
}

void nl_test_got_fdb(struct kbr_proto *p, const net_addr *n, rte *e, int src, bool scan, bool tunnel);

/* "proto mode entry [dev D] source [via G] [vni N] [tunnel]" */
void
nl_test_got_fdb(struct kbr_proto *p, const net_addr *n, rte *e, int src, bool scan, bool tunnel)
{
  static const char *srcs[] = {
    [KBR_SRC_BIRD] = "bird",
    [KBR_SRC_LOCAL] = "local",
    [KBR_SRC_STATIC] = "static",
    [KBR_SRC_DYNAMIC] = "dynamic",
  };

  if (nl_test_routes_pos != nl_test_routes)
    nl_test_routes_add("; ");
  else
    nl_test_routes[0] = 0;

  nl_test_routes_add("%s %s %N", p->p.name, scan ? "scan" : (e ? "add" : "del"), n);

  if (e)
    nl_test_routes_add(" dev %s", e->attrs->nh.iface ? e->attrs->nh.iface->name : "?");

  nl_test_routes_add(" %s", ((src >= 0) && (src < KBR_SRC_MAX)) ? srcs[src] : "?");

  if (e && ipa_nonzero(e->attrs->nh.gw))
    nl_test_routes_add(" via %I", e->attrs->nh.gw);

  if (e && e->attrs->nh.labels)
    nl_test_routes_add(" vni %u", e->attrs->nh.label[0]);

  if (tunnel)
    nl_test_routes_add(" tunnel");

  if (e)
    rte_free(e);
}

/* The captured FDB entry for mac on vid (0 for none) */
static struct nlmsghdr *
nl_test_find_fdb(struct nl_test_capture *c, const byte *mac, uint vid)
{
  for (uint i = 0; i < c->count; i++)
  {
    struct nlmsghdr *h = c->msg[i];
    if ((h->nlmsg_type != RTM_NEWNEIGH) || (((struct ndmsg *) NLMSG_DATA(h))->ndm_family != AF_BRIDGE))
      continue;

    struct rtattr *l = nl_test_find_attr(h, sizeof(struct ndmsg), NDA_LLADDR);
    struct rtattr *v = nl_test_find_attr(h, sizeof(struct ndmsg), NDA_VLAN);
    if (l && (RTA_PAYLOAD(l) == 6) && !memcmp(RTA_DATA(l), mac, 6) && ((v ? rta_get_u16(v) : 0) == vid))
      return h;
  }

  bt_abort_msg("No FDB entry %02x:%02x:%02x:%02x:%02x:%02x vlan %u in the capture",
	       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vid);
  return NULL;
}

/* Parse FDB message h as a scan of br0 does, or as a notification */
static void
nl_test_parse_fdb(struct nlmsghdr *h, int scan)
{
  nl_test_routes_reset();

  if (scan)
  {
    struct iface *br = if_find_by_name("br0");
    struct nl_parse_state s = {
      .pool = nl_linpool,
      .scan = 1,
      .bridge_id = br ? br->index : 0,
    };

    nl_parse_fdb(&s, h);
  }
  else
    nl_async_msg(h);
}

/* The entries of `bridge fdb show br br0` (fdb_show/ip.pcap); br0 is
 * index 3, v0p 4 and v0 5:
 *
 *   33:33:00:00:00:01 dev br0 self permanent        (and three more multicast)
 *   02:00:00:00:00:12 dev v0 vlan 1 master br0
 *   02:00:00:00:00:22 dev v0 vlan 10 master br0 static
 *   02:00:00:00:00:21 dev v0 vlan 10 master br0 static
 *   02:00:00:00:00:21 dev v0 vlan 1 master br0 static
 *   02:00:00:00:00:21 dev v0 master br0 static
 *   02:75:34:b1:37:11 dev v0 vlan 10 master br0 permanent
 *   02:75:34:b1:37:11 dev v0 vlan 1 master br0 permanent
 *   02:75:34:b1:37:11 dev v0 master br0 permanent
 *   33:33:00:00:00:01 dev v0 self permanent         (and one more multicast)
 *
 * `bridge fdb show` with no filter (getneigh_bridge_all) adds v0p's own
 * multicast entries. */
static int
t_parse_fdb_capture(void)
{
  static const struct {
    const char *description;
    const char *capture;
    int vlan_filtering;
    const char *expected;
  } cases[] = {
    { "VLAN filtering: only the entries with a VLAN, no multicast and no self entries (positive)",
      "fdb_show/ip.pcap", 1,
      "kb scan 02:00:00:00:00:12 vlan 1 dev v0 dynamic; "
      "kb scan 02:00:00:00:00:22 vlan 10 dev v0 static; "
      "kb scan 02:00:00:00:00:21 vlan 10 dev v0 static; "
      "kb scan 02:00:00:00:00:21 vlan 1 dev v0 static; "
      "kb scan 02:75:34:b1:37:11 vlan 10 dev v0 local; "
      "kb scan 02:75:34:b1:37:11 vlan 1 dev v0 local" },
    { "no VLAN filtering: only the entries without a VLAN (positive)",
      "fdb_show/ip.pcap", 0,
      "kb scan 02:00:00:00:00:21 dev v0 static; "
      "kb scan 02:75:34:b1:37:11 dev v0 local" },
    { "the whole FDB: v0p is outside the bridge, so the same entries (corner)",
      "fdb_show/netlink_route_getneigh_bridge_all.pcap", 1,
      "kb scan 02:00:00:00:00:12 vlan 1 dev v0 dynamic; "
      "kb scan 02:00:00:00:00:22 vlan 10 dev v0 static; "
      "kb scan 02:00:00:00:00:21 vlan 10 dev v0 static; "
      "kb scan 02:00:00:00:00:21 vlan 1 dev v0 static; "
      "kb scan 02:75:34:b1:37:11 vlan 10 dev v0 local; "
      "kb scan 02:75:34:b1:37:11 vlan 1 dev v0 local" },
  };

  struct kbr_proto *p = nl_test_bridge_setup("fdb_show");

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    struct nl_test_capture fdb;
    char name[128];
    char got[4096];

    bsnprintf(name, sizeof(name), NL_TEST_BRMPLS "%s", cases[i].capture);
    nl_test_load(&fdb, name);
    p->vlan_filtering = cases[i].vlan_filtering;

    got[0] = 0;
    for (uint j = 0; j < fdb.count; j++)
    {
      if (fdb.msg[j]->nlmsg_type != RTM_NEWNEIGH)
	continue;

      nl_test_parse_fdb(fdb.msg[j], 1);
      if (strcmp(nl_test_routes, "none"))
	bsnprintf(got + strlen(got), sizeof(got) - strlen(got), "%s%s", got[0] ? "; " : "", nl_test_routes);
    }

    bt_assert_msg(!strcmp(got, cases[i].expected), "%s: got \"%s\", expected \"%s\"",
		  cases[i].description, got, cases[i].expected);
    nl_test_free(&fdb);
  }

  p->vlan_filtering = 1;
  return 1;
}

enum nl_test_ndm_field {
  NL_NDM_NONE,
  NL_NDM_FAMILY,
  NL_NDM_IFINDEX,
  NL_NDM_STATE,
  NL_NDM_FLAGS,
};

struct nl_test_ndm {
  enum nl_test_ndm_field field;
  uint value;
};

static void
nl_test_ndm_apply(struct ndmsg *n, const struct nl_test_ndm *m)
{
  switch (m->field)
  {
  case NL_NDM_NONE:	break;
  case NL_NDM_FAMILY:	n->ndm_family = m->value; break;
  case NL_NDM_IFINDEX:	n->ndm_ifindex = m->value; break;
  case NL_NDM_STATE:	n->ndm_state = m->value; break;
  case NL_NDM_FLAGS:	n->ndm_flags |= m->value; break;
  }
}

static const byte nl_test_mac22[6] = { 0x02, 0, 0, 0, 0, 0x22 };
static const byte nl_test_mac_short[5] = { 0x02, 0, 0, 0, 0 };
static const byte nl_test_mac_mcast[6] = { 0x01, 0x00, 0x5e, 0, 0, 0x01 };
static const byte nl_test_mac_bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const byte nl_test_mac_zero[6] = { 0 };
static const u16 nl_test_u16_0 = 0;
static const u16 nl_test_u16_4094 = 4094;
static const u16 nl_test_u16_4095 = 4095;
static const u16 nl_test_u16_max = 0xffff;
static const byte nl_test_dst4[4] = { 192, 0, 2, 10 };

#define NL_FDB_EXP	"kb scan 02:00:00:00:00:22 vlan 10 dev v0 static"

/* Changed copies of the captured entry 02:00:00:00:00:22 dev v0 vlan 10
 * master br0 static, in a scan of br0 unless async is set */
static int
t_parse_fdb_changed(void)
{
  static const struct {
    const char *description;
    int async;			/* As a notification, not in a scan */
    int del;			/* As RTM_DELNEIGH */
    int no_vlan_filtering;
    struct nl_test_ndm ndm;
    struct nl_test_attr attr;
    uint msg_len;		/* Truncate the message to this length, 0 keeps it */
    const char *expected;
  } cases[] = {
    /* Modes and sources */
    { .description = "unchanged copy (positive)",
      .expected = NL_FDB_EXP },
    { .description = "notification of a new entry (positive)", .async = 1,
      .expected = "kb add 02:00:00:00:00:22 vlan 10 dev v0 static" },
    { .description = "notification of a deleted entry (positive)", .async = 1, .del = 1,
      .expected = "kb del 02:00:00:00:00:22 vlan 10 static" },
    { .description = "permanent: a local entry (positive)", .ndm = { NL_NDM_STATE, NUD_PERMANENT },
      .expected = "kb scan 02:00:00:00:00:22 vlan 10 dev v0 local" },
    { .description = "reachable: a learned entry (positive)", .ndm = { NL_NDM_STATE, NUD_REACHABLE },
      .expected = "kb scan 02:00:00:00:00:22 vlan 10 dev v0 dynamic" },
    { .description = "externally learned: BIRD's own entry (positive)", .ndm = { NL_NDM_FLAGS, NTF_EXT_LEARNED },
      .expected = "kb scan 02:00:00:00:00:22 vlan 10 dev v0 bird" },

    /* VLAN */
    { .description = "no VLAN on a VLAN filtering bridge (negative)", .attr = { NDA_VLAN, NL_TEST_DROP },
      .expected = "none" },
    { .description = "no VLAN and no VLAN filtering (positive)", .no_vlan_filtering = 1, .attr = { NDA_VLAN, NL_TEST_DROP },
      .expected = "kb scan 02:00:00:00:00:22 dev v0 static" },
    { .description = "a VLAN and no VLAN filtering (negative)", .no_vlan_filtering = 1,
      .expected = "none" },
    { .description = "VLAN 0 is no VLAN (corner)", .attr = { NDA_VLAN, 2, &nl_test_u16_0 },
      .expected = "none" },
    { .description = "VLAN 4094, the highest valid (boundary)", .attr = { NDA_VLAN, 2, &nl_test_u16_4094 },
      .expected = "kb scan 02:00:00:00:00:22 vlan 4094 dev v0 static" },
    { .description = "VLAN 4095, reserved, is taken (boundary)", .attr = { NDA_VLAN, 2, &nl_test_u16_4095 },
      .expected = "kb scan 02:00:00:00:00:22 vlan 4095 dev v0 static" },
    { .description = "VLAN 65535 is taken (boundary)", .attr = { NDA_VLAN, 2, &nl_test_u16_max },
      .expected = "kb scan 02:00:00:00:00:22 vlan 65535 dev v0 static" },
    { .description = "VLAN of 4 bytes (negative)", .attr = { NDA_VLAN, 4, &nl_test_u32_3 },
      .expected = "none" },

    /* MAC address */
    { .description = "no MAC address (negative)", .attr = { NDA_LLADDR, NL_TEST_DROP },
      .expected = "none" },
    { .description = "MAC address of 5 bytes (negative)", .attr = { NDA_LLADDR, 5, nl_test_mac_short },
      .expected = "none" },
    { .description = "multicast MAC address (negative)", .attr = { NDA_LLADDR, 6, nl_test_mac_mcast },
      .expected = "none" },
    { .description = "broadcast MAC address (negative)", .attr = { NDA_LLADDR, 6, nl_test_mac_bcast },
      .expected = "none" },
    { .description = "all-zero MAC address is unicast (corner)", .attr = { NDA_LLADDR, 6, nl_test_mac_zero },
      .expected = "kb scan 00:00:00:00:00:00 vlan 10 dev v0 static" },

    /* Bridge and port */
    { .description = "no NDA_MASTER: the port's master is used (positive)", .attr = { NDA_MASTER, NL_TEST_DROP },
      .expected = NL_FDB_EXP },
    { .description = "NDA_MASTER not the port's master (negative)", .attr = { NDA_MASTER, 4, &nl_test_u32_7 },
      .expected = "none" },
    { .description = "NDA_MASTER of 2 bytes (negative)", .attr = { NDA_MASTER, 2, &nl_test_u16_0 },
      .expected = "none" },
    { .description = "on br0 itself, which has no master (negative)", .ndm = { NL_NDM_IFINDEX, 3 },
      .expected = "none" },
    { .description = "on v0p, outside the bridge (negative)", .ndm = { NL_NDM_IFINDEX, 4 },
      .expected = "none" },
    { .description = "on an unknown interface (negative)", .ndm = { NL_NDM_IFINDEX, 42 },
      .expected = "none" },
    { .description = "self entry on a port that is not VXLAN (negative)", .ndm = { NL_NDM_FLAGS, NTF_SELF },
      .expected = "none" },
    { .description = "NDA_DST on a bridge entry is ignored (corner)", .attr = { NDA_DST, 4, nl_test_dst4 },
      .expected = NL_FDB_EXP },

    /* Header */
    { .description = "AF_INET neighbor (negative)", .ndm = { NL_NDM_FAMILY, AF_INET },
      .expected = "none" },
    { .description = "header only, no attributes (negative)", .msg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
      .expected = "none" },
    { .description = "shorter than the header (negative)", .msg_len = NLMSG_LENGTH(sizeof(struct ndmsg)) - 1,
      .expected = "none" },
  };

  struct nl_test_capture fdb;
  struct kbr_proto *p = nl_test_bridge_setup("fdb_show");
  nl_test_load(&fdb, NL_TEST_BRMPLS "fdb_show/ip.pcap");

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    struct nlmsghdr *h = nl_test_copy(nl_test_find_fdb(&fdb, nl_test_mac22, 10), sizeof(struct ndmsg), &cases[i].attr);
    h->nlmsg_type = cases[i].del ? RTM_DELNEIGH : RTM_NEWNEIGH;
    nl_test_ndm_apply(NLMSG_DATA(h), &cases[i].ndm);

    if (cases[i].msg_len)
      h->nlmsg_len = cases[i].msg_len;

    p->vlan_filtering = !cases[i].no_vlan_filtering;
    nl_test_parse_fdb(h, !cases[i].async);
    nl_test_check_routes(cases[i].description, cases[i].expected);
    xfree(h);
  }

  p->vlan_filtering = 1;
  nl_test_free(&fdb);

  return 1;
}

/* The notifications `ip monitor all` saw while 02:00:00:00:00:21 was added
 * to v0 on VLANs 1 and 10 and without a VLAN, then deleted, and v0p sent a
 * frame from 02:00:00:00:00:12; here c0 is index 3, br0 4, v0p 5, v0 6 */
static int
t_parse_fdb_event(void)
{
  struct nl_test_capture events;
  char got[4096];

  nl_test_bridge_setup("fdb_event");
  nl_test_load(&events, NL_TEST_BRMPLS "fdb_event/ip.pcap");

  got[0] = 0;
  for (uint i = 0; i < events.count; i++)
  {
    if ((events.msg[i]->nlmsg_type != RTM_NEWNEIGH) && (events.msg[i]->nlmsg_type != RTM_DELNEIGH))
      continue;

    nl_test_parse_fdb(events.msg[i], 0);
    if (strcmp(nl_test_routes, "none"))
      bsnprintf(got + strlen(got), sizeof(got) - strlen(got), "%s%s", got[0] ? "; " : "", nl_test_routes);
  }

  /* The entry without a VLAN and the AF_INET neighbor deleted on c0 are
   * skipped */
  const char *expected =
    "kb add 02:00:00:00:00:21 vlan 1 dev v0 static; "
    "kb add 02:00:00:00:00:21 vlan 10 dev v0 static; "
    "kb del 02:00:00:00:00:21 vlan 1 static; "
    "kb del 02:00:00:00:00:21 vlan 10 static; "
    "kb add 02:00:00:00:00:12 vlan 1 dev v0 dynamic";
  bt_assert_msg(!strcmp(got, expected), "FDB events: got \"%s\", expected \"%s\"", got, expected);
  nl_test_free(&events);

  return 1;
}



/*
 *	Bridge VLANs
 */

void nl_test_got_vlan(struct kbr_proto *p, struct iface *i, uint vid, uint flags);
void nl_test_got_vlan_tunnel(struct kbr_proto *p, struct iface *i, uint vid, uint vni, uint flags);

static void
nl_test_record_vlan_flags(uint flags)
{
  static const struct { uint flag; const char *name; } names[] = {
    { BRIDGE_VLAN_INFO_MASTER, "master" },
    { BRIDGE_VLAN_INFO_PVID, "pvid" },
    { BRIDGE_VLAN_INFO_UNTAGGED, "untagged" },
    { BRIDGE_VLAN_INFO_RANGE_BEGIN, "range-begin" },
    { BRIDGE_VLAN_INFO_RANGE_END, "range-end" },
  };

  for (uint j = 0; j < ARRAY_SIZE(names); j++)
    if (flags & names[j].flag)
      nl_test_routes_add(" %s", names[j].name);
}

/* "proto vlan V dev D [flags]" */
void
nl_test_got_vlan(struct kbr_proto *p, struct iface *i, uint vid, uint flags)
{
  if (nl_test_routes_pos != nl_test_routes)
    nl_test_routes_add("; ");
  else
    nl_test_routes[0] = 0;

  nl_test_routes_add("%s vlan %u dev %s", p->p.name, vid, i->name);
  nl_test_record_vlan_flags(flags);
}

/* "proto vlan V dev D vni N [flags]" */
void
nl_test_got_vlan_tunnel(struct kbr_proto *p, struct iface *i, uint vid, uint vni, uint flags)
{
  if (nl_test_routes_pos != nl_test_routes)
    nl_test_routes_add("; ");
  else
    nl_test_routes[0] = 0;

  nl_test_routes_add("%s vlan %u dev %s vni %u", p->p.name, vid, i->name, vni);
  nl_test_record_vlan_flags(flags);
}

/* The AF_BRIDGE link message of interface name in capture c */
static struct nlmsghdr *
nl_test_find_brlink(struct nl_test_capture *c, const char *name)
{
  for (uint i = 0; i < c->count; i++)
    if ((c->msg[i]->nlmsg_type == RTM_NEWLINK) &&
	(((struct ifinfomsg *) NLMSG_DATA(c->msg[i]))->ifi_family == AF_BRIDGE) &&
	!strcmp(nl_test_link_name(c->msg[i]), name))
      return c->msg[i];

  bt_abort_msg("No AF_BRIDGE link %s in the capture", name);
  return NULL;
}

/* Parse link message h as a VLAN scan of bridge_id does */
static void
nl_test_parse_vlan(struct nlmsghdr *h, uint bridge_id)
{
  struct nl_parse_state s = {
    .pool = nl_linpool,
    .scan = 1,
    .bridge_id = bridge_id,
  };

  nl_test_routes_reset();
  nl_parse_vlan(&s, h);
}

/* The AF_BRIDGE entries of `bridge vlan show` (vlan_show's
 * netlink_route_getlink_brvlan.pcap); br0 is index 3, v0p 4 and v0 5:
 *
 *   br0   1 PVID Egress Untagged
 *         10
 *   v0    1 Egress Untagged
 *         10
 *         20 Egress Untagged     (and each of 21 to 30)
 *         40 PVID Egress Untagged
 *
 * The kernel lists every VLAN on its own, as BIRD does not ask for ranges.
 * br0's own entry has IFLA_MASTER br0, so its VLANs are taken as those of
 * a port. */
static int
t_parse_vlan_capture(void)
{
  static const struct {
    const char *description;
    int vlan_filtering;
    int other_bridge;		/* Scan of a bridge with another index */
    const char *expected;
  } cases[] = {
    { "VLAN filtering: br0's VLANs and v0's (positive, br0's a corner)", 1, 0,
      "kb vlan 1 dev br0 pvid untagged; kb vlan 10 dev br0; "
      "kb vlan 1 dev v0 untagged; kb vlan 10 dev v0; "
      "kb vlan 20 dev v0 untagged; kb vlan 21 dev v0 untagged; kb vlan 22 dev v0 untagged; "
      "kb vlan 23 dev v0 untagged; kb vlan 24 dev v0 untagged; kb vlan 25 dev v0 untagged; "
      "kb vlan 26 dev v0 untagged; kb vlan 27 dev v0 untagged; kb vlan 28 dev v0 untagged; "
      "kb vlan 29 dev v0 untagged; kb vlan 30 dev v0 untagged; "
      "kb vlan 40 dev v0 pvid untagged" },
    { "no VLAN filtering: none (negative)", 0, 0,
      "" },
    { "scan of another bridge: none (negative)", 1, 1,
      "" },
  };

  struct nl_test_capture vlans;
  struct kbr_proto *p = nl_test_bridge_setup("vlan_show");
  nl_test_load(&vlans, NL_TEST_BRMPLS "vlan_show/netlink_route_getlink_brvlan.pcap");

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    char got[4096];
    got[0] = 0;

    p->vlan_filtering = cases[i].vlan_filtering;
    for (uint j = 0; j < vlans.count; j++)
    {
      if (vlans.msg[j]->nlmsg_type != RTM_NEWLINK)
	continue;

      nl_test_parse_vlan(vlans.msg[j], kbr_bridge_id(p) + cases[i].other_bridge);
      if (strcmp(nl_test_routes, "none"))
	bsnprintf(got + strlen(got), sizeof(got) - strlen(got), "%s%s", got[0] ? "; " : "", nl_test_routes);
    }

    bt_assert_msg(!strcmp(got, cases[i].expected), "%s: got \"%s\", expected \"%s\"",
		  cases[i].description, got, cases[i].expected);
  }

  p->vlan_filtering = 1;
  nl_test_free(&vlans);

  return 1;
}

/* An attribute of an IFLA_AF_SPEC list, see nl_test_vlan_spec() */
struct nl_test_spec {
  u16 type;
  u16 len;
  const void *data;
};

#define NL_TEST_MAX_SPEC 4

/* Write attributes e into buf, as an IFLA_AF_SPEC payload, and return its
 * length */
static uint
nl_test_vlan_spec(byte *buf, uint size, const struct nl_test_spec *e)
{
  uint pos = 0;

  for (uint i = 0; (i < NL_TEST_MAX_SPEC) && e[i].type; i++)
  {
    struct rtattr *a = (struct rtattr *) (buf + pos);
    ASSERT(pos + RTA_SPACE(e[i].len) <= size);

    memset(a, 0, RTA_SPACE(e[i].len));
    a->rta_type = e[i].type;
    a->rta_len = RTA_LENGTH(e[i].len);
    if (e[i].len)
      memcpy(RTA_DATA(a), e[i].data, e[i].len);
    pos += RTA_SPACE(e[i].len);
  }

  return pos;
}

enum nl_test_ifi_field {
  NL_IFI_NONE,
  NL_IFI_FAMILY,
  NL_IFI_INDEX,
};

static const struct bridge_vlan_info nl_test_vi10 = { .vid = 10 };
static const struct bridge_vlan_info nl_test_vi1_pvid = { .flags = BRIDGE_VLAN_INFO_PVID | BRIDGE_VLAN_INFO_UNTAGGED, .vid = 1 };
static const struct bridge_vlan_info nl_test_vi0 = { .vid = 0 };
static const struct bridge_vlan_info nl_test_vi4094 = { .vid = 4094 };
static const struct bridge_vlan_info nl_test_vi4095 = { .vid = 4095 };
static const struct bridge_vlan_info nl_test_vi_begin = { .flags = BRIDGE_VLAN_INFO_RANGE_BEGIN, .vid = 20 };
static const struct bridge_vlan_info nl_test_vi_end = { .flags = BRIDGE_VLAN_INFO_RANGE_END, .vid = 30 };
static const struct bridge_vlan_info nl_test_vi_master = { .flags = BRIDGE_VLAN_INFO_MASTER, .vid = 10 };
static const byte nl_test_vi_short[2] = { 0, 0 };

/* IFLA_BRIDGE_VLAN_TUNNEL_INFO payloads, little-endian */
static const byte nl_test_tun_vni100[] = {
  8, 0, IFLA_BRIDGE_VLAN_TUNNEL_ID, 0, 100, 0, 0, 0,
  6, 0, IFLA_BRIDGE_VLAN_TUNNEL_VID, 0, 10, 0, 0, 0,
  6, 0, IFLA_BRIDGE_VLAN_TUNNEL_FLAGS, 0, 0, 0, 0, 0,
};
static const byte nl_test_tun_no_id[] = {
  6, 0, IFLA_BRIDGE_VLAN_TUNNEL_VID, 0, 10, 0, 0, 0,
};
static const byte nl_test_tun_short_id[] = {
  6, 0, IFLA_BRIDGE_VLAN_TUNNEL_ID, 0, 100, 0, 0, 0,
  6, 0, IFLA_BRIDGE_VLAN_TUNNEL_VID, 0, 10, 0, 0, 0,
};
static const byte nl_test_tun_range[] = {
  8, 0, IFLA_BRIDGE_VLAN_TUNNEL_ID, 0, 0xff, 0xff, 0xff, 0,
  6, 0, IFLA_BRIDGE_VLAN_TUNNEL_VID, 0, 20, 0, 0, 0,
  6, 0, IFLA_BRIDGE_VLAN_TUNNEL_FLAGS, 0, BRIDGE_VLAN_INFO_RANGE_BEGIN, 0, 0, 0,
};

#define NL_VI(x)	{ IFLA_BRIDGE_VLAN_INFO, sizeof(struct bridge_vlan_info), &x }
#define NL_TUN(x)	{ IFLA_BRIDGE_VLAN_TUNNEL_INFO, sizeof(x), x }

/* Changed copies of v0's captured AF_BRIDGE entry, in a scan of br0;
 * IFLA_AF_SPEC is replaced by spec when given */
static int
t_parse_vlan_changed(void)
{
  static const struct {
    const char *description;
    const char *link;		/* "v0" unless given */
    int del;			/* As RTM_DELLINK */
    int no_vlan_filtering;
    enum nl_test_ifi_field ifi;
    uint ifi_value;
    struct nl_test_attr attr;
    struct nl_test_spec spec[NL_TEST_MAX_SPEC];
    const char *expected;
  } cases[] = {
    /* VLAN info */
    { .description = "one VLAN (positive)", .spec = { NL_VI(nl_test_vi10) },
      .expected = "kb vlan 10 dev v0" },
    { .description = "PVID, untagged (positive)", .spec = { NL_VI(nl_test_vi1_pvid) },
      .expected = "kb vlan 1 dev v0 pvid untagged" },
    { .description = "two VLANs, in order (positive)", .spec = { NL_VI(nl_test_vi1_pvid), NL_VI(nl_test_vi10) },
      .expected = "kb vlan 1 dev v0 pvid untagged; kb vlan 10 dev v0" },
    { .description = "the master flag is passed on (corner)", .spec = { NL_VI(nl_test_vi_master) },
      .expected = "kb vlan 10 dev v0 master" },
    { .description = "VLAN 0 is passed on (boundary)", .spec = { NL_VI(nl_test_vi0) },
      .expected = "kb vlan 0 dev v0" },
    { .description = "VLAN 4094, the highest valid (boundary)", .spec = { NL_VI(nl_test_vi4094) },
      .expected = "kb vlan 4094 dev v0" },
    { .description = "VLAN 4095, reserved, is passed on (boundary)", .spec = { NL_VI(nl_test_vi4095) },
      .expected = "kb vlan 4095 dev v0" },
    { .description = "a range comes as its two ends only, which BIRD does not ask for (corner)",
      .spec = { NL_VI(nl_test_vi_begin), NL_VI(nl_test_vi_end) },
      .expected = "kb vlan 20 dev v0 range-begin; kb vlan 30 dev v0 range-end" },
    { .description = "VLAN info of 2 bytes is skipped (negative)",
      .spec = { { IFLA_BRIDGE_VLAN_INFO, 2, nl_test_vi_short } },
      .expected = "none" },
    { .description = "VLAN info of 2 bytes, the next one is still taken (corner)",
      .spec = { { IFLA_BRIDGE_VLAN_INFO, 2, nl_test_vi_short }, NL_VI(nl_test_vi10) },
      .expected = "kb vlan 10 dev v0" },
    { .description = "VLAN info of 8 bytes is skipped (negative)",
      .spec = { { IFLA_BRIDGE_VLAN_INFO, 8, nl_test_tun_vni100 }, NL_VI(nl_test_vi10) },
      .expected = "kb vlan 10 dev v0" },
    { .description = "unknown attribute in the list is ignored (corner)",
      .spec = { { IFLA_BRIDGE_MODE, 2, &nl_test_u16_0 }, NL_VI(nl_test_vi10) },
      .expected = "kb vlan 10 dev v0" },
    { .description = "empty list (boundary)", .attr = { IFLA_AF_SPEC, 0, NULL },
      .expected = "none" },

    /* Tunnel info */
    { .description = "VLAN 10 mapped to VNI 100 (positive)", .spec = { NL_TUN(nl_test_tun_vni100) },
      .expected = "kb vlan 10 dev v0 vni 100" },
    { .description = "tunnel info without an ID is VNI 0 (corner)", .spec = { NL_TUN(nl_test_tun_no_id) },
      .expected = "kb vlan 10 dev v0 vni 0" },
    { .description = "tunnel ID of 2 bytes, the entry is skipped (negative)",
      .spec = { NL_TUN(nl_test_tun_short_id), NL_VI(nl_test_vi10) },
      .expected = "kb vlan 10 dev v0" },
    { .description = "the highest VNI on a range start (boundary)", .spec = { NL_TUN(nl_test_tun_range) },
      .expected = "kb vlan 20 dev v0 vni 16777215 range-begin" },
    { .description = "empty tunnel info is VLAN 0, VNI 0 (corner)",
      .spec = { { IFLA_BRIDGE_VLAN_TUNNEL_INFO, 0, NULL } },
      .expected = "kb vlan 0 dev v0 vni 0" },

    /* Bridge and port */
    { .description = "no IFLA_MASTER (negative)", .attr = { IFLA_MASTER, NL_TEST_DROP },
      .expected = "none" },
    { .description = "IFLA_MASTER of another bridge (negative)", .attr = { IFLA_MASTER, 4, &nl_test_u32_7 },
      .expected = "none" },
    { .description = "IFLA_MASTER of 2 bytes, the message is rejected (negative)", .attr = { IFLA_MASTER, 2, &nl_test_u16_0 },
      .expected = "none" },
    { .description = "no IFLA_AF_SPEC (negative)", .attr = { IFLA_AF_SPEC, NL_TEST_DROP },
      .expected = "none" },
    { .description = "no VLAN filtering (negative)", .no_vlan_filtering = 1,
      .expected = "none" },
    { .description = "on an unknown interface (negative)", .ifi = NL_IFI_INDEX, .ifi_value = 42,
      .expected = "none" },
    { .description = "AF_UNSPEC link (negative)", .ifi = NL_IFI_FAMILY, .ifi_value = AF_UNSPEC,
      .expected = "none" },
    { .description = "br0's own entry, which names itself as master (corner)", .link = "br0",
      .expected = "kb vlan 1 dev br0 pvid untagged; kb vlan 10 dev br0" },
    { .description = "v0's entry under br0's index, as br0's own (corner)", .ifi = NL_IFI_INDEX, .ifi_value = 3,
      .spec = { NL_VI(nl_test_vi10) },
      .expected = "kb vlan 10 dev br0" },
    { .description = "br0's own entry with IFLA_MASTER of another bridge (negative)", .link = "br0",
      .attr = { IFLA_MASTER, 4, &nl_test_u32_7 },
      .expected = "none" },
    { .description = "a port of index 1, lo (boundary)", .ifi = NL_IFI_INDEX, .ifi_value = 1,
      .spec = { NL_VI(nl_test_vi10) },
      .expected = "kb vlan 10 dev lo" },
    { .description = "a port of index 2^31-1, unknown (boundary)", .ifi = NL_IFI_INDEX, .ifi_value = 0x7fffffff,
      .spec = { NL_VI(nl_test_vi10) },
      .expected = "none" },
    { .description = "RTM_DELLINK is read like RTM_NEWLINK, scans have none (corner)", .del = 1,
      .spec = { NL_VI(nl_test_vi10) },
      .expected = "kb vlan 10 dev v0" },
  };

  struct nl_test_capture vlans;
  struct kbr_proto *p = nl_test_bridge_setup("vlan_show");
  nl_test_load(&vlans, NL_TEST_BRMPLS "vlan_show/netlink_route_getlink_brvlan.pcap");

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    byte spec[256];
    struct nl_test_attr attr = cases[i].attr;

    if (cases[i].spec[0].type)
      attr = (struct nl_test_attr) { IFLA_AF_SPEC, nl_test_vlan_spec(spec, sizeof(spec), cases[i].spec), spec };

    struct nlmsghdr *h = nl_test_copy(nl_test_find_brlink(&vlans, cases[i].link ?: "v0"), sizeof(struct ifinfomsg), &attr);
    struct ifinfomsg *ifi = NLMSG_DATA(h);
    h->nlmsg_type = cases[i].del ? RTM_DELLINK : RTM_NEWLINK;

    if (cases[i].ifi == NL_IFI_FAMILY)
      ifi->ifi_family = cases[i].ifi_value;
    else if (cases[i].ifi == NL_IFI_INDEX)
      ifi->ifi_index = cases[i].ifi_value;

    p->vlan_filtering = !cases[i].no_vlan_filtering;
    nl_test_parse_vlan(h, kbr_bridge_id(p));
    nl_test_check_routes(cases[i].description, cases[i].expected);
    xfree(h);
  }

  p->vlan_filtering = 1;
  nl_test_free(&vlans);

  return 1;
}

/* The notifications `bridge monitor vlan` saw while VLANs 10 and 20-30 were
 * added to v0 and 10 deleted (after the canary 4000) */
static int
t_parse_vlan_event(void)
{
  struct nl_test_capture events;
  char got[4096];

  nl_test_bridge_setup("vlan_event");
  nl_test_load(&events, NL_TEST_BRMPLS "vlan_event/ip.pcap");

  got[0] = 0;
  uint n = 0;
  for (uint i = 0; i < events.count; i++)
  {
    if ((events.msg[i]->nlmsg_type != RTM_NEWVLAN) && (events.msg[i]->nlmsg_type != RTM_DELVLAN))
      continue;

    nl_test_routes_reset();
    nl_async_msg(events.msg[i]);
    n++;
    if (strcmp(nl_test_routes, "none"))
      bsnprintf(got + strlen(got), sizeof(got) - strlen(got), "%s%s", got[0] ? "; " : "", nl_test_routes);
  }

  /* RTM_NEWVLAN and RTM_DELVLAN are not read; the VLANs come from scans */
  bt_assert_msg(n == 4, "VLAN events: %u notifications, expected 4", n);
  bt_assert_msg(!strcmp(got, ""), "VLAN events: got \"%s\", expected none", got);
  nl_test_free(&events);

  return 1;
}

/* br0's IFLA_LINKINFO with IFLA_INFO_DATA holding only data, little-endian */
#define NL_TEST_BR_LINKINFO(...)					\
  12, 0, IFLA_INFO_KIND, 0, 'b', 'r', 'i', 'd', 'g', 'e', 0, 0,	\
  __VA_ARGS__

static const byte nl_test_br_filtering1[] = { NL_TEST_BR_LINKINFO(12, 0, IFLA_INFO_DATA, 0, 5, 0, IFLA_BR_VLAN_FILTERING, 0, 1, 0, 0, 0) };
static const byte nl_test_br_filtering0[] = { NL_TEST_BR_LINKINFO(12, 0, IFLA_INFO_DATA, 0, 5, 0, IFLA_BR_VLAN_FILTERING, 0, 0, 0, 0, 0) };
static const byte nl_test_br_filtering_pad[] = { NL_TEST_BR_LINKINFO(12, 0, IFLA_INFO_DATA, 0, 5, 0, IFLA_BR_VLAN_FILTERING, 0, 1, 0xff, 0xff, 0xff) };
static const byte nl_test_br_filtering_u32[] = { NL_TEST_BR_LINKINFO(12, 0, IFLA_INFO_DATA, 0, 8, 0, IFLA_BR_VLAN_FILTERING, 0, 1, 0, 0, 0) };
static const byte nl_test_br_no_filtering[] = { NL_TEST_BR_LINKINFO(4, 0, IFLA_INFO_DATA, 0) };
static const byte nl_test_br_no_data[] = { NL_TEST_BR_LINKINFO() };

/* The links of the bridge rows: br0's VLAN filtering flag from its link
 * message, and the AF_BRIDGE link notifications the kernel sends for br0 and
 * its ports to the link group BIRD listens to, which are not links */
static int
t_parse_bridge_link(void)
{
  static const struct {
    const char *description;
    const char *link;
    int bridge;			/* The AF_BRIDGE message, not the AF_UNSPEC one */
    int del;			/* As RTM_DELLINK */
    struct nl_test_attr attr;
    const char *expected;
  } cases[] = {
    /* IFLA_BR_VLAN_FILTERING, a u8 */
    { "br0 as captured: a bridge with VLAN filtering (positive)", "br0", 0, 0, {},
      "br0 index 3 mtu 1500 admin-up multiaccess broadcast multicast bridge vlan-filtering 1 lladdr 56:6f:f3:24:7b:da" },
    { "VLAN filtering on (positive)", "br0", 0, 0, { IFLA_LINKINFO, sizeof(nl_test_br_filtering1), nl_test_br_filtering1 },
      "br0 index 3 mtu 1500 admin-up multiaccess broadcast multicast bridge vlan-filtering 1 lladdr 56:6f:f3:24:7b:da" },
    { "VLAN filtering off (positive)", "br0", 0, 0, { IFLA_LINKINFO, sizeof(nl_test_br_filtering0), nl_test_br_filtering0 },
      "br0 index 3 mtu 1500 admin-up multiaccess broadcast multicast bridge vlan-filtering 0 lladdr 56:6f:f3:24:7b:da" },
    { "VLAN filtering on, the padding after it set (corner)", "br0", 0, 0,
      { IFLA_LINKINFO, sizeof(nl_test_br_filtering_pad), nl_test_br_filtering_pad },
      "br0 index 3 mtu 1500 admin-up multiaccess broadcast multicast bridge vlan-filtering 1 lladdr 56:6f:f3:24:7b:da" },
    { "VLAN filtering of 4 bytes is not taken (negative)", "br0", 0, 0,
      { IFLA_LINKINFO, sizeof(nl_test_br_filtering_u32), nl_test_br_filtering_u32 },
      "br0 index 3 mtu 1500 admin-up multiaccess broadcast multicast bridge lladdr 56:6f:f3:24:7b:da" },
    { "no VLAN filtering attribute (negative)", "br0", 0, 0,
      { IFLA_LINKINFO, sizeof(nl_test_br_no_filtering), nl_test_br_no_filtering },
      "br0 index 3 mtu 1500 admin-up multiaccess broadcast multicast bridge lladdr 56:6f:f3:24:7b:da" },
    { "no IFLA_INFO_DATA: not even a bridge (corner)", "br0", 0, 0,
      { IFLA_LINKINFO, sizeof(nl_test_br_no_data), nl_test_br_no_data },
      "br0 index 3 mtu 1500 admin-up multiaccess broadcast multicast lladdr 56:6f:f3:24:7b:da" },

    /* AF_BRIDGE notifications */
    { "v0's AF_BRIDGE RTM_NEWLINK leaves v0 as it is (positive)", "v0", 1, 0, {},
      "v0 index 5 mtu 1500 admin-up multiaccess broadcast multicast master br0 lladdr 56:6f:f3:24:7b:da" },
    { "v0's AF_BRIDGE RTM_DELLINK (port removed, or RTM_DELVLAN) does not delete v0 (negative)", "v0", 1, 1, {},
      "v0 index 5 mtu 1500 admin-up multiaccess broadcast multicast master br0 lladdr 56:6f:f3:24:7b:da" },
    { "br0's AF_BRIDGE RTM_NEWLINK keeps br0 a bridge with VLAN filtering (negative)", "br0", 1, 0, {},
      "br0 index 3 mtu 1500 admin-up multiaccess broadcast multicast bridge vlan-filtering 1 lladdr 56:6f:f3:24:7b:da" },
    { "v0's own RTM_DELLINK still deletes v0 (positive)", "v0", 0, 1, {}, "none" },
  };

  struct nl_test_capture links, vlans;
  nl_test_bridge_setup("vlan_show");
  nl_test_load(&links, NL_TEST_BRMPLS "vlan_show/netlink_route_getlink.pcap");
  nl_test_load(&vlans, NL_TEST_BRMPLS "vlan_show/netlink_route_getlink_brvlan.pcap");

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    nl_test_load_ns("vlan_show");

    struct nlmsghdr *base = cases[i].bridge ?
      nl_test_find_brlink(&vlans, cases[i].link) : nl_test_find_link(&links, cases[i].link);
    struct nlmsghdr *h = nl_test_copy(base, sizeof(struct ifinfomsg), &cases[i].attr);
    h->nlmsg_type = cases[i].del ? RTM_DELLINK : RTM_NEWLINK;

    nl_async_msg(h);
    nl_test_check_iface(cases[i].description, if_find_by_name(cases[i].link), cases[i].expected);
    xfree(h);
  }

  nl_test_free(&links);
  nl_test_free(&vlans);

  return 1;
}

#endif


int
main(int argc, char *argv[])
{
  bt_init(argc, argv);
  bt_bird_init();

  bt_test_suite(t_parse_link_bridge, "Bridge links built in host byte order");

  /* The captures are of a little-endian host, and netlink messages are in
   * host byte order */
#ifdef CPU_BIG_ENDIAN
  bt_debug("The captures are little-endian, skipping their tests\n");
  return bt_exit_value();
#endif

  bt_test_suite(t_parse_link_capture, "Links from a captured link dump");
  bt_test_suite(t_parse_link_changed, "Links with one attribute changed");
  bt_test_suite(t_parse_link_update, "Changes to known links");
  bt_test_suite(t_parse_link_kinds, "Links of other kinds from captures");
  bt_test_suite(t_parse_addr_capture, "Addresses from a captured address dump");
  bt_test_suite(t_parse_addr_changed, "Addresses with one field or attribute changed");
  bt_test_suite(t_parse_addr_show, "Addresses of the addr-show captures");
  bt_test_suite(t_parse_route_capture, "Routes from a captured route dump");
  bt_test_suite(t_parse_route_sadr, "Routes from a captured route dump on a SADR channel");
  bt_test_suite(t_parse_route_changed, "Routes with one field or attribute changed");
  bt_test_suite(t_parse_route_multipath, "Multipath routes");
  bt_test_suite(t_parse_route_matrix, "Routes from the ip route matrix captures");
  bt_test_suite(t_parse_route_get, "Routes of the ip route get captures");
  bt_test_suite(t_parse_monitor, "Notifications of the ip monitor capture");
  bt_test_suite(t_parse_error, "Kernel acknowledgements and errors from the ip route matrix captures");
#ifdef HAVE_MPLS_KERNEL
  bt_test_suite(t_parse_mpls_capture, "MPLS routes and MPLS encapsulation from captures");
  bt_test_suite(t_parse_mpls_event, "MPLS route notifications from a capture");
#endif
#ifdef CONFIG_BRIDGE
  bt_test_suite(t_parse_fdb_capture, "Bridge FDB entries from captured dumps");
  bt_test_suite(t_parse_fdb_changed, "Bridge FDB entries with one field or attribute changed");
  bt_test_suite(t_parse_fdb_event, "Bridge FDB notifications from a capture");
  bt_test_suite(t_parse_vlan_capture, "Bridge VLANs from a captured dump");
  bt_test_suite(t_parse_vlan_changed, "Bridge VLANs with one attribute changed");
  bt_test_suite(t_parse_vlan_event, "Bridge VLAN notifications from a capture");
  bt_test_suite(t_parse_bridge_link, "Bridge links and AF_BRIDGE link notifications");
#endif

  return bt_exit_value();
}
