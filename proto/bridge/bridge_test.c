/*
 *	BIRD -- Bridge protocol tests
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/*
 * kbr_check_iface() is static, so this file includes bridge.c, and the
 * Makefile leaves bridge.o out of the test's link.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "proto/bridge/bridge.c"

#include "sysdep/unix/unix.h"

/* The log, written to memory to check what was logged */
static char *kbr_test_log_buf;
static size_t kbr_test_log_size;
static size_t kbr_test_log_pos;

static void
kbr_test_log_init(void)
{
  static struct log_config lc = { .mask = ~0, .terminal_flag = 1 };
  static list logs;
  lc.fh = open_memstream(&kbr_test_log_buf, &kbr_test_log_size);
  bt_assert(lc.fh);
  init_list(&logs);
  add_tail(&logs, &lc.n);
  log_switch(0, &logs, NULL);
}

/* The last line logged since the previous call, without "bird: " */
static const char *
kbr_test_last_log(void)
{
  static char line[256];
  line[0] = 0;

  for (size_t i = kbr_test_log_pos; i < kbr_test_log_size; )
  {
    const char *s = kbr_test_log_buf + i;
    const char *e = memchr(s, '\n', kbr_test_log_size - i);
    size_t len = e ? (size_t) (e - s) : kbr_test_log_size - i;

    if (!strncmp(s, "bird: ", 6))
      bsnprintf(line, sizeof(line), "%.*s", (int) (len - 6), s + 6);

    i += len + 1;
  }

  kbr_test_log_pos = kbr_test_log_size;
  return line;
}

/* An interface attribute the row leaves out */
#define KBR_TEST_NONE	U32_UNDEF

static int
t_check_iface(void)
{
  struct {
    const char *description;
    const char *name;
    uint flags;
    bool no_attrs;		/* i->attrs is NULL */
    u32 type;			/* EA_IFACE_TYPE, or KBR_TEST_NONE */
    u32 vlan_filtering;		/* EA_IFACE_BRIDGE_VLAN_FILTERING, or KBR_TEST_NONE */
    int proto_vlan_filtering;
    const char *expected;	/* The result, and what was logged */
  } cases[] = {
    { "bridge, both VLAN filtering (positive)",
      "br-odd.4094", IF_UP, false, IF_TYPE_BRIDGE, 1, 1,
      "1" },
    { "bridge, neither VLAN filtering (positive)",
      "br-odd.4094", IF_UP, false, IF_TYPE_BRIDGE, 0, 0,
      "1" },
    { "bridge VLAN filtering, the protocol not (positive)",
      "br-odd.4094", IF_UP, false, IF_TYPE_BRIDGE, 1, 0,
      "1" },
    { "the protocol VLAN filtering, the bridge not (negative)",
      "br-odd.4094", IF_UP, false, IF_TYPE_BRIDGE, 0, 1,
      "0 kbr1: Interface br-odd.4094 has no VLAN filtering" },
    { "a VXLAN interface (negative)",
      "vx-odd.4094", IF_UP, false, IF_TYPE_VXLAN, KBR_TEST_NONE, 1,
      "0 kbr1: Interface vx-odd.4094 is not a bridge" },
    { "no interface type (negative)",
      "eth0", IF_UP, false, KBR_TEST_NONE, KBR_TEST_NONE, 0,
      "0 kbr1: Interface eth0 is not a bridge" },
    { "no attributes at all (negative)",
      "eth0", IF_UP, true, KBR_TEST_NONE, KBR_TEST_NONE, 0,
      "0 kbr1: Interface eth0 is not a bridge" },
    { "bridge down (negative)",
      "br-odd.4094", 0, false, IF_TYPE_BRIDGE, 1, 1,
      "0" },
    { "bridge without the VLAN filtering attribute, taken as filtering (boundary)",
      "br-odd.4094", IF_UP, false, IF_TYPE_BRIDGE, KBR_TEST_NONE, 1,
      "1" },
    { "VLAN filtering 255, as the kernel's u8 could give (boundary)",
      "br-odd.4094", IF_UP, false, IF_TYPE_BRIDGE, 255, 1,
      "1" },
    { "a 15 character name, the longest Linux allows (corner)",
      "br-15-char-name", IF_UP, false, IF_TYPE_BRIDGE, 0, 1,
      "0 kbr1: Interface br-15-char-name has no VLAN filtering" },
    { "up, a bridge, and other flags set (corner)",
      "br0", IF_UP | IF_MULTIACCESS | IF_BROADCAST | IF_MULTICAST, false, IF_TYPE_BRIDGE, 1, 1,
      "1" },
  };

  kbr_test_log_init();

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    struct kbr_proto p = { .vlan_filtering = cases[i].proto_vlan_filtering };
    p.p.name = "kbr1";

    struct rta rta = {};
    struct iface iface = {
      .flags = cases[i].flags,
      .attrs = cases[i].no_attrs ? NULL : &rta,
    };
    strcpy(iface.name, cases[i].name);

    if (cases[i].type != KBR_TEST_NONE)
      ea_set_attr_u32(&rta.eattrs, tmp_linpool, EA_IFACE_TYPE, 0, EAF_TYPE_INT, cases[i].type);

    if (cases[i].vlan_filtering != KBR_TEST_NONE)
      ea_set_attr_u32(&rta.eattrs, tmp_linpool, EA_IFACE_BRIDGE_VLAN_FILTERING, 0, EAF_TYPE_INT, cases[i].vlan_filtering);

    kbr_test_last_log();
    bool res = kbr_check_iface(&p, &iface);
    const char *log = kbr_test_last_log();

    char got[256];
    bsnprintf(got, sizeof(got), "%d%s%s", res, *log ? " " : "", log);
    bt_assert_msg(!strcmp(got, cases[i].expected),
		  "%s: got \"%s\", expected \"%s\"", cases[i].description, got, cases[i].expected);

    lp_flush(tmp_linpool);
  }

  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);
  bt_bird_init();

  bt_test_suite(t_check_iface, "Checking the bridge interface");

  return bt_exit_value();
}
