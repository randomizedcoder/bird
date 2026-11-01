/*
 *	Filters: Parser Tests
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "filter/filter.h"
#include "conf/conf.h"

#define PROTO "protocol device { }\n"

static const char *parse_pos;
static uint parse_len;

static int
parse_read(byte *dest, uint max_len, int fd UNUSED)
{
  if (max_len > parse_len)
    max_len = parse_len;
  memcpy(dest, parse_pos, max_len);
  parse_pos += max_len;
  parse_len -= max_len;
  return max_len;
}

/* Parse a config, never commit it; return its error message, or NULL, and
 * its router ID */
static const char *
parse(const char *text, char *err, size_t err_len, u32 *router_id)
{
  struct config *cfg = config_alloc("parse");
  parse_pos = text;
  parse_len = strlen(text);
  cf_read_hook = parse_read;

  const char *res = NULL;
  if (!config_parse(cfg))
  {
    bsnprintf(err, err_len, "%s", cfg->err_msg);
    res = err;
  }

  if (router_id)
    *router_id = cfg->router_id;

  config_free(cfg);
  return res;
}

/* The router ID, a number or an IPv4 address; 0 picks one at commit */
static int
t_parse_router_id(void)
{
  static const struct {
    const char *description;
    const char *config;
    const char *expected;		/* Router ID, or "error: " and the message */
  } cases[] = {
    /* IPv4 addresses */
    { "IPv4 address (positive)", "router id 192.0.2.1;", "192.0.2.1" },
    { "lowest IPv4 address but 0 (boundary)", "router id 0.0.0.1;", "0.0.0.1" },
    { "highest IPv4 address (boundary)", "router id 255.255.255.255;", "255.255.255.255" },
    { "0.0.0.0, the same as none (corner)", "router id 0.0.0.0;", "0.0.0.0" },
    { "multicast address (corner)", "router id 224.0.0.5;", "224.0.0.5" },
    { "loopback address (corner)", "router id 127.0.0.1;", "127.0.0.1" },
    { "IPv4 octet out of range (negative)", "router id 192.0.2.256;", "error: Invalid IPv4 address 192.0.2.256" },
    { "IPv4 address with three octets (negative)", "router id 192.0.2;", "error: syntax error, unexpected '.', expecting ';'" },
    { "IPv4 prefix (negative)", "router id 192.0.2.0/24;", "error: syntax error, unexpected '/', expecting ';'" },

    /* Numbers */
    { "number (positive)", "router id 1;", "0.0.0.1" },
    { "highest number (boundary)", "router id 4294967295;", "255.255.255.255" },
    { "number over 32 bits (negative)", "router id 4294967296;", "error: Number out of range" },
    { "0 (corner)", "router id 0;", "0.0.0.0" },
    { "hexadecimal number (positive)", "router id 0xc0000201;", "192.0.2.1" },
    { "expression (positive)", "router id (3 * 256 + 4);", "0.0.3.4" },
    { "negative expression, taken as 32 bits (corner)", "router id (0 - 1);", "255.255.255.255" },

    /* Constants */
    { "IPv4 constant (positive)", "define RID = 192.0.2.7; router id RID;", "192.0.2.7" },
    { "number constant (positive)", "define RID = 7; router id RID;", "0.0.0.7" },
    { "pair constant (negative)", "define RID = (1, 2); router id RID;", "error: Number or IPv4 address expected" },
    { "string constant (negative)", "define RID = \"192.0.2.1\"; router id RID;", "error: Number or IPv4 address expected" },
    { "IPv6 constant (negative)", "define RID = 2001:db8::1; router id RID;", "error: Number or IPv4 address expected" },
    { "IPv4-mapped IPv6 constant, taken as IPv4 unlike the address itself (corner)", "define RID = ::ffff:192.0.2.1; router id RID;", "192.0.2.1" },

    /* IPv6 */
    { "IPv6 address (negative)", "router id 2001:db8::1;", "error: syntax error, unexpected IP6" },
    { "IPv6 unspecified address (negative)", "router id ::;", "error: syntax error, unexpected IP6" },
    { "IPv4-mapped IPv6 address (negative)", "router id ::ffff:192.0.2.1;", "error: syntax error, unexpected IP6" },

    /* Others */
    { "string (negative)", "router id \"192.0.2.1\";", "error: syntax error, unexpected TEXT" },
    { "missing (negative)", "router id;", "error: syntax error, unexpected ';'" },
    { "none (positive)", "", "0.0.0.0" },
    { "given twice, the last one taken (corner)", "router id 192.0.2.1; router id 192.0.2.2;", "192.0.2.2" },
    { "from interfaces, picked at commit (positive)", "router id from \"eth*\";", "0.0.0.0" },
  };

  char text[1024], err[256], got[256];

  for (uint i = 0; i < ARRAY_SIZE(cases); i++)
  {
    u32 rid = 0;
    bsnprintf(text, sizeof(text), "%s\n" PROTO, cases[i].config);
    const char *res = parse(text, err, sizeof(err), &rid);

    if (res)
      bsnprintf(got, sizeof(got), "error: %s", res);
    else
      bsnprintf(got, sizeof(got), "%R", rid);

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

  bt_test_suite(t_parse_router_id, "Router IDs");

  bt_bird_cleanup();
  return bt_exit_value();
}
