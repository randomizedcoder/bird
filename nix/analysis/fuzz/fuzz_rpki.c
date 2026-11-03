/*
 *	libFuzzer harness: RPKI-to-Router (RFC 6810, 8210, ASPA draft) PDUs.
 *
 *	Reachable from the configured RPKI cache server, or anyone able to
 *	inject into its TCP session: rpki_rx_hook() framing,
 *	rpki_check_receive_packet() (version negotiation and downgrade,
 *	PDU type and minimum length), the byte-order conversion of every
 *	PDU type incl. Error Report with an encapsulated PDU and ASPA, then
 *	the handlers: Serial Notify, Cache Response, IPv4/IPv6 Prefix
 *	(ROA import into the roa4/roa6 tables), ASPA (provider lists into
 *	the aspa table), End of Data (interval checks), Cache Reset, Error,
 *	and the Error Report replies (sent through the stubbed socket).
 *
 *	The real startup path runs: the protocol connects over the stubbed
 *	TCP socket (fuzz_sock.h), the harness fires the connected hook, and
 *	BIRD sends its Reset Query. rpki_cache_change_state() is wrapped, so
 *	the fatal/transport/reconnect states a bad PDU leads to are recorded
 *	instead of tearing the cache down; every input starts from one of the
 *	session states below.
 *
 *	Input: one control byte, then a stream of PDUs (framed by their own
 *	length fields, as on the wire).
 *	  bit 0     0 = new session: Reset Query sent, expecting Cache
 *	              Response (request_session_id set)
 *	            1 = synchronized: session id 0x4242, serial 1, Established
 *	  bits 1-2  negotiated protocol version (0, 1, 2; 3 = 2)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "fuzz_sock.h"

#include "proto/rpki/rpki.h"

#define FUZZ_RPKI_SESSION	0x4242

#define FUZZ_RPKI_CONFIG						\
  "router id 10.0.0.1;\n"						\
  "roa4 table r4;\n"							\
  "roa6 table r6;\n"							\
  "aspa table at;\n"							\
  "protocol rpki rp {\n"						\
  "  roa4 { table r4; };\n"						\
  "  roa6 { table r6; };\n"						\
  "  aspa { table at; };\n"						\
  "  remote 10.0.0.10 port 323;\n"					\
  "  min version 0;\n"							\
  "  max version 2;\n"							\
  "}\n"

static struct rpki_proto *fuzz_p;
static uint fuzz_rpki_errors;

void __real_rpki_cache_change_state(struct rpki_cache *cache, const enum rpki_cache_state new_state);
void __wrap_rpki_cache_change_state(struct rpki_cache *cache, const enum rpki_cache_state new_state);

/* Calls from packets.c. The error states close the socket or restart the
 * protocol; record them and keep the session. */
void
__wrap_rpki_cache_change_state(struct rpki_cache *cache, const enum rpki_cache_state new_state)
{
  switch (new_state)
  {
  case RPKI_CS_ERROR_FATAL:
  case RPKI_CS_ERROR_TRANSPORT:
  case RPKI_CS_FAST_RECONNECT:
    cache->state = new_state;
    cache->tr_sock->sk_closed = true;	/* Stop rpki_rx_hook() like a close would */
    fuzz_rpki_errors++;
    if (fuzz_verbose())
      fprintf(stderr, "fuzz: rpki state %s (kept session)\n", rpki_cache_state_to_str(new_state));
    return;

  default:
    __real_rpki_cache_change_state(cache, new_state);
  }
}

static void
fuzz_setup(void)
{
  fuzz_bird_init(FUZZ_RPKI_CONFIG);

  fuzz_p = (struct rpki_proto *) fuzz_proto_find(&proto_rpki, "rp");

  struct rpki_cache *cache = fuzz_p->cache;
  sock *sk = (cache && cache->tr_sock) ? cache->tr_sock->sk : NULL;

  if (!sk || !sk->tx_hook)
  {
    fprintf(stderr, "fuzz: rpki did not open its socket\n");
    abort();
  }

  sk->tx_hook(sk);			/* rpki_connected_hook(): Reset Query */
  fuzz_pump();

  if ((fuzz_p->p.proto_state != PS_UP) || (cache->state != RPKI_CS_SYNC_START))
  {
    fprintf(stderr, "fuzz: rpki not connected (proto %u, cache %s)\n",
	    fuzz_p->p.proto_state, rpki_cache_state_to_str(cache->state));
    abort();
  }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FUZZ_ONCE(fuzz_setup());

  uint8_t ctl = fuzz_take_byte(&data, &size);
  struct rpki_cache *cache = fuzz_p->cache;
  sock *sk = cache->tr_sock->sk;
  uint version = (ctl >> 1) & 3;

  if (size > sk->rbsize)
    return 0;

  cache->version = MIN(version, RPKI_MAX_VERSION);
  cache->tr_sock->sk_closed = false;

  if (ctl & 1)
  {
    cache->state = RPKI_CS_ESTABLISHED;
    cache->request_session_id = 0;
    cache->session_id = FUZZ_RPKI_SESSION;
    cache->serial_num = 1;
  }
  else
  {
    cache->state = RPKI_CS_SYNC_START;
    cache->request_session_id = 1;
    cache->session_id = 0;
    cache->serial_num = 0;
  }

  fuzz_sk_feed(sk, data, size, NULL);
  fuzz_pump();

  return 0;
}
