/*
 *	libFuzzer harness: BGP OPEN on a connection in OpenSent.
 *
 *	Reachable from any TCP peer that connects to (or accepts from) a
 *	configured neighbor, before any authentication beyond TCP-MD5/AO:
 *	bgp_rx_open(), bgp_read_options() (incl. RFC 9072 extended optional
 *	parameters), bgp_read_capabilities() for every capability, the
 *	hold/keepalive/AS/router ID/role checks and collision handling.
 *
 *	Input: one control byte, then the message body.
 *	  bit 0  0: OPEN body (header added by the harness)
 *	         1: raw byte stream, framed by the input itself
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "fuzz_bgp_common.h"

static struct bgp_proto *fuzz_p;
static struct bgp_conn *fuzz_conn;
static byte fuzz_buf[BGP_RX_BUFFER_SIZE];

static void
fuzz_setup(void)
{
  char *cfg = malloc(strlen(fuzz_log_config()) + sizeof(FUZZ_BGP_CONFIG));

  strcpy(cfg, fuzz_log_config());
  strcat(cfg, FUZZ_BGP_CONFIG);
  fuzz_bird_init(cfg);

  fuzz_p = fuzz_bgp_find("peer_e");
  fuzz_conn = fuzz_bgp_connect(fuzz_p);
}

/* Undo what one OPEN left behind, so every input sees a fresh OpenSent. */
static void
fuzz_reset(void)
{
  struct bgp_conn *conn = fuzz_conn;

  if (conn->remote_caps)
  {
    mb_free(conn->remote_caps);
    conn->remote_caps = NULL;
  }
  if (conn->remote_open_msg)
  {
    mb_free(conn->remote_open_msg);
    conn->remote_open_msg = NULL;
  }
  conn->remote_open_length = 0;
  conn->as4_session = conn->ext_messages = 0;
  fuzz_p->remote_id = 0;
  conn->state = BS_OPENSENT;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FUZZ_ONCE(fuzz_setup());

  uint8_t ctl = fuzz_take_byte(&data, &size);
  uint len;

  if (ctl & 1)
  {
    if (size > sizeof(fuzz_buf))
      return 0;
    memcpy(fuzz_buf, data, size);
    len = size;
  }
  else
  {
    if (size > sizeof(fuzz_buf) - BGP_HEADER_LENGTH)
      return 0;
    len = BGP_HEADER_LENGTH + size;
    fuzz_bgp_header(fuzz_buf, len, PKT_OPEN);
    memcpy(fuzz_buf + BGP_HEADER_LENGTH, data, size);
  }

  fuzz_bgp_feed(fuzz_conn, fuzz_buf, len);
  fuzz_pump();
  fuzz_reset();

  return 0;
}
