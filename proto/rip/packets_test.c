/*
 *	BIRD -- RIP packet tests
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/*
 * rip_check_authentication() is static, so this file includes packets.c,
 * and the Makefile leaves packets.o out of the test's link.
 *
 * Authentication (RFC 2453, RFC 4822) is a RIPv2 feature; RIPng has none,
 * so the packets here are all RIPv2, over IPv4.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "proto/rip/packets.c"

#include "lib/unaligned.h"
#include "sysdep/unix/unix.h"

#define RIP_TEST_NBR	"192.0.2.2"

static struct rip_proto rip_test_proto;
static struct rip_iface rip_test_ifa;
static struct rip_iface_config rip_test_cf;
static struct iface rip_test_iface;
static struct neighbor rip_test_nbr;
static struct rip_neighbor rip_test_n;
static list rip_test_passwords;
static struct password_item rip_test_pass[2];

/* The log, written to memory to check what was logged */
static char *rip_test_log_buf;
static size_t rip_test_log_size;
static size_t rip_test_log_pos;

static void
rip_test_init(void)
{
  rip_test_proto.p.name = "rip1";
  rip_test_iface = (struct iface) { .name = "eth-odd.4094" };
  rip_test_ifa = (struct rip_iface) {
    .rip = &rip_test_proto,
    .iface = &rip_test_iface,
    .cf = &rip_test_cf,
  };
  rip_test_nbr = (struct neighbor) { .addr = ipa_from_ip4(ip4_build(192, 0, 2, 2)) };

  init_list(&rip_test_passwords);
  rip_test_pass[0] = (struct password_item) {
    .password = "secret", .length = 6, .id = 1, .alg = ALG_MD5,
    .accto = TIME_INFINITY, .gento = TIME_INFINITY,
  };
  rip_test_pass[1] = (struct password_item) {
    .password = "0123456789abcdef0123456789abcdef", .length = 32, .id = 255, .alg = ALG_HMAC_SHA256,
    .accto = TIME_INFINITY, .gento = TIME_INFINITY,
  };

  static struct log_config lc = { .mask = ~0, .terminal_flag = 1 };
  static list logs;
  lc.fh = open_memstream(&rip_test_log_buf, &rip_test_log_size);
  bt_assert(lc.fh);
  init_list(&logs);
  add_tail(&logs, &lc.n);
  log_switch(0, &logs, NULL);
}

/* The last line logged since the previous call, without "bird: " */
static const char *
rip_test_last_log(void)
{
  static char line[256];
  line[0] = 0;

  for (size_t i = rip_test_log_pos; i < rip_test_log_size; )
  {
    const char *s = rip_test_log_buf + i;
    const char *e = memchr(s, '\n', rip_test_log_size - i);
    size_t len = e ? (size_t) (e - s) : rip_test_log_size - i;

    if (!strncmp(s, "bird: ", 6))
      bsnprintf(line, sizeof(line), "%.*s", (int) (len - 6), s + 6);

    i += len + 1;
  }

  rip_test_log_pos = rip_test_log_size;
  return line;
}

/* What the test does to a signed packet */
enum rip_test_edit {
  RIP_TEST_NONE,
  RIP_TEST_KEY_ID,		/* Change the key ID */
  RIP_TEST_ENTRY,		/* Change a byte of a route entry */
  RIP_TEST_TRAILER,		/* Change the trailer's 0xffff */
  RIP_TEST_PKT_LEN,		/* Set packet_len to .value, and the length to match */
  RIP_TEST_PLEN,		/* Hand over .value as the packet's length */
};

/*
 * Signs a packet of @data_len bytes (header, authentication entry and route
 * entries) as rip_fill_authentication() does, but byte by byte, so that
 * @data_len need not keep the trailer aligned. Returns the packet's length.
 */
static uint
rip_test_sign(byte *pkt, uint hdr_len, uint data_len, struct password_item *pass, uint auth_len_field, u32 seq)
{
  byte *auth = pkt + hdr_len;
  uint auth_len = mac_type_length(pass->alg);

  put_u16(auth, 0xffff);
  put_u16(auth + 2, RIP_AUTH_CRYPTO);
  put_u16(auth + 4, data_len);
  auth[6] = pass->id;
  auth[7] = auth_len_field;
  put_u32(auth + 8, seq);
  memset(auth + 12, 0, 8);

  byte *tail = pkt + data_len;
  put_u16(tail, 0xffff);
  put_u16(tail + 2, 0x0001);

  byte key[MAX_HASH_SIZE];
  if (pass->alg < ALG_HMAC)
    memcpy0(key, pass->password, auth_len, pass->length);
  else
    for (uint i = 0; i < auth_len; i += 4)
    {
      /* In network order already, as memset32() stores it */
      u32 magic = HMAC_MAGIC;
      memcpy(key + i, &magic, 4);
    }
  memcpy(tail + 4, key, auth_len);

  uint plen = data_len + sizeof(struct rip_auth_tail) + auth_len;
  byte mac[MAX_HASH_SIZE];
  mac_fill(pass->alg, pass->password, pass->length, pkt, plen, mac);
  memcpy(tail + 4, mac, auth_len);

  return plen;
}

static int
t_check_authentication(void)
{
  static const struct {
    const char *description;
    int pass;			/* Index into rip_test_pass[] */
    int demand;			/* Demand circuit, so an update header */
    uint entries;		/* Route entries */
    int pad;			/* Bytes after the route entries, before the trailer */
    int real_fill;		/* Signed by rip_fill_authentication() itself */
    int auth_len;		/* auth_len field, or 0 for what bird sends */
    u32 seq;			/* Sequence number sent */
    u32 csn;			/* Last one received from the neighbor */
    enum rip_test_edit edit;
    uint value;
    const char *expected;
  } cases[] = {
    /* positive */
    { "Keyed MD5, 1 route entry, signed by bird (positive)",
      0, 0, 1, 0, 1, 0, 0, 0, RIP_TEST_NONE, 0,
      "1 plen 44" },
    { "HMAC-SHA256, 25 route entries, signed by bird (positive)",
      1, 0, 25, 0, 1, 0, 0, 0, RIP_TEST_NONE, 0,
      "1 plen 524" },
    { "Keyed MD5, demand circuit update header, signed by bird (positive)",
      0, 1, 2, 0, 1, 0, 0, 0, RIP_TEST_NONE, 0,
      "1 plen 68" },
    { "Keyed MD5, 1 route entry, signed by the test (positive)",
      0, 0, 1, 0, 0, 0, 7, 0, RIP_TEST_NONE, 0,
      "1 plen 44" },
    { "HMAC-SHA256, 3 route entries, signed by the test (positive)",
      1, 0, 3, 0, 0, 0, 7, 0, RIP_TEST_NONE, 0,
      "1 plen 84" },
    { "Keyed MD5, auth_len 16 (the other interpretation, positive)",
      0, 0, 1, 0, 0, 16, 7, 0, RIP_TEST_NONE, 0,
      "1 plen 44" },
    { "higher sequence number (positive)",
      0, 0, 1, 0, 0, 0, 101, 100, RIP_TEST_NONE, 0,
      "1 plen 44" },

    /* negative */
    { "unknown key ID (negative)",
      0, 0, 1, 0, 1, 0, 0, 0, RIP_TEST_KEY_ID, 0,
      "0 plen 64 rip1: Authentication failed for " RIP_TEST_NBR " on eth-odd.4094 - no suitable password found (2)" },
    { "changed route entry, wrong MAC (negative)",
      0, 0, 1, 0, 1, 0, 0, 0, RIP_TEST_ENTRY, 0,
      "0 plen 64 rip1: Authentication failed for " RIP_TEST_NBR " on eth-odd.4094 - wrong authentication code (1)" },
    { "trailer without 0xffff (negative)",
      1, 0, 1, 0, 1, 0, 0, 0, RIP_TEST_TRAILER, 0,
      "0 plen 80 rip1: Authentication failed for " RIP_TEST_NBR " on eth-odd.4094 - authentication trailer is missing (0)" },
    { "auth_len 17 (negative)",
      0, 0, 1, 0, 0, 17, 7, 0, RIP_TEST_NONE, 0,
      "0 plen 64 rip1: Authentication failed for " RIP_TEST_NBR " on eth-odd.4094 - wrong authentication length (17)" },
    { "lower sequence number (negative)",
      0, 0, 1, 0, 0, 0, 99, 100, RIP_TEST_NONE, 0,
      "0 plen 64 rip1: Authentication failed for " RIP_TEST_NBR " on eth-odd.4094 - lower sequence number (rcv 99, old 100)" },
    { "packet a byte longer than packet_len says (negative)",
      0, 0, 1, 0, 0, 0, 7, 0, RIP_TEST_PLEN, 65,
      "0 plen 65 rip1: Authentication failed for " RIP_TEST_NBR " on eth-odd.4094 - packet length mismatch (65)" },

    /* boundary */
    { "no route entries, just the authentication entry (boundary)",
      0, 0, 0, 0, 0, 0, 7, 0, RIP_TEST_NONE, 0,
      "1 plen 24" },
    { "packet_len 4, the trailer on the authentication entry (boundary)",
      0, 0, 0, 0, 0, 0, 7, 0, RIP_TEST_PKT_LEN, 4,
      "0 plen 24 rip1: Authentication failed for " RIP_TEST_NBR " on eth-odd.4094 - authentication trailer is missing (0)" },
    { "packet_len 20, the trailer inside the authentication entry (boundary)",
      0, 0, 0, 0, 0, 0, 7, 0, RIP_TEST_PKT_LEN, 20,
      "0 plen 40 rip1: Authentication failed for " RIP_TEST_NBR " on eth-odd.4094 - authentication trailer is missing (0)" },
    { "packet_len 0, too short for the authentication entry (boundary)",
      0, 0, 0, 0, 0, 0, 7, 0, RIP_TEST_PKT_LEN, 0,
      "0 plen 20 rip1: Authentication failed for " RIP_TEST_NBR " on eth-odd.4094 - authentication method mismatch (0)" },

    /* corner: valid MACs over a trailer that is not after whole entries,
     * so misaligned; accepted, and rip_rx_hook() drops them later */
    { "Keyed MD5, 1 byte after the route entries (corner)",
      0, 0, 1, 1, 0, 0, 7, 0, RIP_TEST_NONE, 0,
      "1 plen 45" },
    { "Keyed MD5, 2 bytes after the route entries (corner)",
      0, 0, 1, 2, 0, 0, 7, 0, RIP_TEST_NONE, 0,
      "1 plen 46" },
    { "HMAC-SHA256, 19 bytes after the route entries (corner)",
      1, 0, 1, 19, 0, 0, 7, 0, RIP_TEST_NONE, 0,
      "1 plen 63" },
    { "HMAC-SHA256, demand circuit, 3 bytes short of a route entry (corner)",
      1, 1, 1, -3, 0, 0, 7, 0, RIP_TEST_NONE, 0,
      "1 plen 45" },
  };

  rip_test_init();

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    struct password_item *pass = &rip_test_pass[cases[i].pass];

    /* Only the row's key is valid, as one key is used per interface */
    init_list(&rip_test_passwords);
    add_tail(&rip_test_passwords, &pass->n);

    rip_test_cf = (struct rip_iface_config) {
      .version = RIP_V2,
      .auth_type = RIP_AUTH_CRYPTO,
      .demand_circuit = cases[i].demand,
      .passwords = &rip_test_passwords,
    };
    rip_test_ifa.csn = cases[i].seq;
    rip_test_ifa.csn_ready = !!cases[i].seq;
    rip_test_n = (struct rip_neighbor) {
      .ifa = &rip_test_ifa, .nbr = &rip_test_nbr, .csn = cases[i].csn, .uc = 1,
    };
    rip_test_proto.log_pkt_tbf = (struct tbf) TBF_DEFAULT_LOG_LIMITS;

    /* Room for 25 entries and the longest trailer, kept aligned as rbuf is */
    u64 buf[(600 + 7) / 8] = {};
    byte *pkt = (byte *) buf;
    uint hdr_len = sizeof(struct rip_packet) + (cases[i].demand ? sizeof(struct rip_update_hdr) : 0);
    uint data_len = hdr_len + RIP_BLOCK_LENGTH + cases[i].entries * RIP_BLOCK_LENGTH + cases[i].pad;
    uint plen;

    pkt[0] = cases[i].demand ? RIP_CMD_UPDATE_RESPONSE : RIP_CMD_RESPONSE;
    pkt[1] = RIP_V2;
    if (cases[i].demand)
      pkt[4] = RIP_UPDATE_VERSION;

    for (uint j = 0; j < cases[i].entries; j++)
    {
      byte *e = pkt + hdr_len + RIP_BLOCK_LENGTH * (j + 1);
      put_u16(e, RIP_AF_IPV4);
      put_u32(e + 4, 0xc6336400 + j);	/* 198.51.100.x */
      put_u32(e + 8, 0xffffffff);
      put_u32(e + 16, 1);
    }

    if (cases[i].real_fill)
    {
      plen = data_len;
      rip_fill_authentication(&rip_test_proto, &rip_test_ifa, (struct rip_packet *) pkt, &plen);
    }
    else
      plen = rip_test_sign(pkt, hdr_len, data_len, pass,
			   cases[i].auth_len ? (uint) cases[i].auth_len : mac_type_length(pass->alg) +
			   ((pass->alg < ALG_HMAC) ? sizeof(struct rip_auth_tail) : 0),
			   cases[i].seq);

    switch (cases[i].edit)
    {
    case RIP_TEST_NONE:					break;
    case RIP_TEST_KEY_ID:	pkt[hdr_len + 6]++;		break;
    case RIP_TEST_ENTRY:	pkt[hdr_len + RIP_BLOCK_LENGTH + 7]++;	break;
    case RIP_TEST_TRAILER:	pkt[data_len]--;		break;
    case RIP_TEST_PKT_LEN:
      put_u16(pkt + hdr_len + 4, cases[i].value);
      plen = cases[i].value + sizeof(struct rip_auth_tail) + mac_type_length(pass->alg);
      break;
    case RIP_TEST_PLEN:		plen = cases[i].value;		break;
    }

    rip_test_last_log();
    int res = rip_check_authentication(&rip_test_proto, &rip_test_ifa, (struct rip_packet *) pkt, &plen, hdr_len, &rip_test_n);
    const char *log = rip_test_last_log();

    char got[256];
    bsnprintf(got, sizeof(got), "%d plen %u%s%s", res, plen, *log ? " " : "", log);
    bt_assert_msg(!strcmp(got, cases[i].expected),
		  "%s: got \"%s\", expected \"%s\"", cases[i].description, got, cases[i].expected);
  }

  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);
  bt_bird_init();

  bt_test_suite(t_check_authentication, "RIPv2 cryptographic authentication");

  return bt_exit_value();
}
