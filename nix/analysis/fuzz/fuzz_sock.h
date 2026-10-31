/*
 *	Socket layer stubs shared by the protocol harnesses.
 *
 *	fuzz.mk links every protocol harness with FUZZ_SOCK_WRAPS, so the
 *	protocols' own calls into sysdep/unix/io.c land here instead:
 *
 *	  sk_open()     sets the address family and allocates the buffers,
 *	                opens no descriptor (fd = -1); SK_MAGIC sockets (an
 *	                fd the caller already has, e.g. a pipe) keep theirs
 *	  sk_send(), sk_send_to()
 *	                report the data as sent
 *	  sk_setup_multicast(), sk_join_group(), sk_leave_group(),
 *	  sk_setup_broadcast(), sk_set_ttl(), sk_set_min_ttl(),
 *	  sk_set_ipv6_checksum()
 *	                succeed; the real ones fail on fd -1 and the
 *	                protocols would then close the socket
 *
 *	fuzz_sk_feed() then delivers a datagram exactly as sk_read() would:
 *	the data in rbuf and the per-datagram fields the rx hooks check.
 *
 *	--wrap only redirects calls between objects, so io.c's own internal
 *	calls are unaffected.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_NIX_FUZZ_SOCK_H_
#define _BIRD_NIX_FUZZ_SOCK_H_

#include <sys/socket.h>

#include "fuzz_bird.h"

#include "lib/socket.h"
#include "nest/iface.h"

int __wrap_sk_open(sock *s);
int __wrap_sk_send(sock *s, uint len);
int __wrap_sk_send_to(sock *s, uint len, ip_addr to, uint port);
int __wrap_sk_setup_multicast(sock *s);
int __wrap_sk_join_group(sock *s, ip_addr maddr);
int __wrap_sk_leave_group(sock *s, ip_addr maddr);
int __wrap_sk_setup_broadcast(sock *s);
int __wrap_sk_set_ttl(sock *s, int ttl);
int __wrap_sk_set_min_ttl(sock *s, int ttl);
int __wrap_sk_set_ipv6_checksum(sock *s, int offset);

static uint fuzz_sk_sent;

int
__wrap_sk_open(sock *s)
{
  /* The address family as the real sk_open() picks it; sk_rx_buffer()
   * strips an IPv4 header from SK_IP sockets based on it. */
  if (s->type <= SK_IP)
  {
    if (s->subtype == SK_IPV4)
      s->af = AF_INET;
    else if (s->subtype == SK_IPV6)
      s->af = AF_INET6;
    else
      s->af = (ipa_is_ip4(s->saddr) || ipa_is_ip4(s->daddr)) ? AF_INET : AF_INET6;
  }

  if (!s->rbuf && s->rbsize)
    s->rbuf = s->rbuf_alloc = xmalloc(s->rbsize);
  s->rpos = s->rbuf;
  if (!s->tbuf && s->tbsize)
    s->tbuf = s->tbuf_alloc = xmalloc(s->tbsize);
  s->tpos = s->ttx = s->tbuf;
  if (s->type != SK_MAGIC)
    s->fd = -1;
  return 0;
}

int
__wrap_sk_send(sock *s, uint len UNUSED)
{
  s->ttx = s->tpos = s->tbuf;
  fuzz_sk_sent++;
  return 1;
}

int
__wrap_sk_send_to(sock *s, uint len UNUSED, ip_addr to UNUSED, uint port UNUSED)
{
  s->ttx = s->tpos = s->tbuf;
  fuzz_sk_sent++;
  return 1;
}

int __wrap_sk_setup_multicast(sock *s UNUSED) { return 0; }
int __wrap_sk_join_group(sock *s UNUSED, ip_addr maddr UNUSED) { return 0; }
int __wrap_sk_leave_group(sock *s UNUSED, ip_addr maddr UNUSED) { return 0; }
int __wrap_sk_setup_broadcast(sock *s UNUSED) { return 0; }
int __wrap_sk_set_ttl(sock *s UNUSED, int ttl UNUSED) { return 0; }
int __wrap_sk_set_min_ttl(sock *s UNUSED, int ttl UNUSED) { return 0; }
int __wrap_sk_set_ipv6_checksum(sock *s UNUSED, int offset UNUSED) { return 0; }

/* Per-datagram fields, as sk_read() fills them for UDP and raw IP. */
struct fuzz_dgram {
  ip_addr faddr, laddr;		/* source, destination */
  uint fport;			/* source port (UDP) */
  struct iface *iface;		/* receiving interface (lifindex) */
  int ttl;			/* received TTL / hop limit */
};

/* Deliver one datagram (or stream chunk) to the socket's rx_hook, copied
 * into the socket's own rbuf (rbsize bytes, heap). d may be NULL for
 * stream sockets. Returns the hook's result. */
static int
fuzz_sk_feed(sock *sk, const byte *data, uint len, const struct fuzz_dgram *d)
{
  if (!sk || !sk->rx_hook || !sk->rbuf)
    return 0;

  if (len > sk->rbsize)
    len = sk->rbsize;

  memcpy(sk->rbuf, data, len);
  sk->rpos = sk->rbuf + len;
  sk->flags &= ~SKF_TRUNCATED;

  if (d)
  {
    sk->faddr = d->faddr;
    sk->laddr = d->laddr;
    sk->fport = d->fport;
    sk->lifindex = d->iface ? d->iface->index : 0;
    sk->rcv_ttl = d->ttl;
  }

  int rv = sk->rx_hook(sk, len);

  /* Each input starts from an empty buffer; a partial stream message
   * left by the hook is dropped rather than carried into the next one. */
  sk->rpos = sk->rbuf;

  return rv;
}

#endif
