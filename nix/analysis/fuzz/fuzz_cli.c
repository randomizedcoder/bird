/*
 *	libFuzzer harness: commands on the CLI control socket.
 *
 *	Reachable from anyone allowed to connect to bird.ctl (or a
 *	restricted CLI socket, `cli "..." { restrict; }`): cli_command() and
 *	cli_parse() (the command half of the bison grammar, with the flex
 *	lexer in CLI mode), every `show` command and its continuation
 *	(routes with filters and `where` expressions, protocols, interfaces,
 *	symbols, memory, status, ROA/ASPA), `eval` (the filter compiler and
 *	interpreter on arbitrary expressions), `echo`, `debug`, `timeformat`,
 *	protocol enable/disable/restart/reload, `dump` and `mrt dump`, and
 *	the output formatting and buffering in nest/cli.c.
 *
 *	There is no socket: birdtest.c already stubs the sysdep side of the
 *	CLI, and fuzz.mk wraps it again (-Wl,--wrap):
 *	  cli_get_command()    returns the next input line as the command
 *	  cli_write_trigger()  reads the queued output (so ASan checks it),
 *	                       then frees it as a completed write would;
 *	                       with FUZZ_VERBOSE, commands and output go to
 *	                       stderr
 *	  cmd_dump_file()      runs the dump into a scratch file (it is opened
 *	                       O_EXCL), deleted again, whatever file the
 *	                       command names
 *	  mrt_dump_cmd()       runs the dump into /dev/null
 *	`configure`, `down` and `graceful restart` are birdtest.c no-op stubs.
 *
 *	Input: one control byte, then command lines separated by '\n'.
 *	  bit 0  0 = unrestricted CLI, 1 = restricted CLI
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "fuzz_iface.h"

#include "nest/cli.h"
#include "proto/mrt/mrt.h"

#define FUZZ_CLI_CONFIG							\
  "router id 10.0.0.1;\n"						\
  FUZZ_DEVICE_CONFIG							\
  "ipv4 table t4b;\n"							\
  "roa4 table r4;\n"							\
  "aspa table at;\n"							\
  "flow4 table f4;\n"							\
  "vpn4 table v4;\n"							\
  "define LOCAL_AS = 65000;\n"						\
  "function fz_tag(int x) -> int { return x * 2 + LOCAL_AS; }\n"	\
  "filter fz_in {\n"							\
  "  if net ~ [ 10.0.0.0/8+ ] then { bgp_community.add((65000, 1)); accept; }\n" \
  "  if net.len > 24 then reject;\n"					\
  "  accept;\n"								\
  "}\n"									\
  "protocol static s4 {\n"						\
  "  ipv4 { import filter fz_in; };\n"					\
  "  route 10.1.0.0/16 via 10.0.0.2;\n"					\
  "  route 10.2.0.0/24 blackhole;\n"					\
  "  route 10.3.0.0/24 via 10.0.0.2 { bgp_med = 10; bgp_path.prepend(65001); };\n" \
  "  route 192.0.2.0/24 unreachable;\n"					\
  "}\n"									\
  "protocol static s6 {\n"						\
  "  ipv6;\n"								\
  "  route 2001:db8:100::/48 via 2001:db8::2;\n"			\
  "  route 2001:db8:200::/48 prohibit;\n"				\
  "}\n"									\
  "protocol static sroa { roa4 { table r4; }; route 10.0.0.0/8 max 24 as 65001; }\n" \
  "protocol static saspa { aspa { table at; }; route aspa 65001 providers 65002, 65003; }\n" \
  "protocol static sflow { flow4 { table f4; }; route flow4 { dst 10.0.0.0/8; dport 80; }; }\n" \
  "protocol static svpn { vpn4 { table v4; }; route 65000:1 10.9.0.0/16 blackhole; }\n" \
  "protocol pipe p4 { table master4; peer table t4b; export all; import none; }\n"

#include <unistd.h>

static cli *fuzz_cli[2];
static char fuzz_dump_path[256];
static const byte *fuzz_pos, *fuzz_end;

int __wrap_cli_get_command(cli *c);
void __wrap_cli_write_trigger(cli *c);
void __real_cmd_dump_file(struct cli *cli, const char *file, const char *what, void (*dump)(struct dump_request *));
void __wrap_cmd_dump_file(struct cli *cli, const char *file, const char *what, void (*dump)(struct dump_request *));
void __real_mrt_dump_cmd(struct mrt_dump_data *d);
void __wrap_mrt_dump_cmd(struct mrt_dump_data *d);

/* Next input line into rx_buf, as sysdep/unix/main.c cli_get_command()
 * copies it from the socket: CR dropped, at most CLI_RX_BUF_SIZE-2. */
int
__wrap_cli_get_command(cli *c)
{
  if (fuzz_pos >= fuzz_end)
    return 0;

  const byte *nl = memchr(fuzz_pos, '\n', fuzz_end - fuzz_pos);
  const byte *eol = nl ?: fuzz_end;
  byte *d = c->rx_buf;
  int too_long = 0;

  for (const byte *s = fuzz_pos; s < eol; s++)
  {
    if (*s == '\r')
      continue;
    if (d >= c->rx_buf + CLI_RX_BUF_SIZE - 2)
    {
      too_long = 1;
      break;
    }
    *d++ = *s;
  }
  *d = 0;

  fuzz_pos = nl ? nl + 1 : fuzz_end;

  if (fuzz_verbose())
    fprintf(stderr, "fuzz: cli> %s\n", c->rx_buf);

  return too_long ? -1 : 1;
}

void
__wrap_cli_write_trigger(cli *c)
{
  volatile byte sink = 0;

  for (struct cli_out *o = c->tx_pos; o; o = o->next)
  {
    for (byte *b = o->outpos; b < o->wpos; b++)
      sink ^= *b;

    if (fuzz_verbose())
      fwrite(o->outpos, 1, o->wpos - o->outpos, stderr);
  }
  (void) sink;

  if (c->tx_pos)
    cli_written(c);
}

void
__wrap_cmd_dump_file(struct cli *cli, const char *file UNUSED, const char *what,
		     void (*dump)(struct dump_request *))
{
  unlink(fuzz_dump_path);
  __real_cmd_dump_file(cli, fuzz_dump_path, what, dump);
  unlink(fuzz_dump_path);
}

void
__wrap_mrt_dump_cmd(struct mrt_dump_data *d)
{
  if (d->filename)
    d->filename = "/dev/null";
  __real_mrt_dump_cmd(d);
}

static void
fuzz_setup(void)
{
  /* Memory-backed when /dev/shm exists */
  const char *dir = access("/dev/shm", W_OK) ? (getenv("TMPDIR") ?: "/tmp") : "/dev/shm";
  snprintf(fuzz_dump_path, sizeof(fuzz_dump_path), "%s/bird-fuzz-cli-dump.%d", dir, (int) getpid());

  fuzz_bird_init(FUZZ_CLI_CONFIG);
  fuzz_iface_add(0);
  cli_init();

  static struct cli_config cf[2] = { { .restricted = 0 }, { .restricted = 1 } };

  for (int i = 0; i < 2; i++)
  {
    fuzz_cli[i] = cli_new(NULL, &cf[i]);
    fuzz_cli[i]->rx_pos = fuzz_cli[i]->rx_buf;
  }

  fuzz_pump();				/* cli_hello */
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FUZZ_ONCE(fuzz_setup());

  uint8_t ctl = fuzz_take_byte(&data, &size);
  cli *c = fuzz_cli[ctl & 1];

  if (size > 16384)
    return 0;

  fuzz_pos = data;
  fuzz_end = data + size;

  ev_schedule(c->event);
  fuzz_pump();

  /* A long `show` may still be running (c->cont); let it finish so the
   * next input starts with a fresh command, within a bound. */
  for (int i = 0; (i < 64) && (c->cont || c->tx_pos); i++)
  {
    ev_schedule(c->event);
    fuzz_pump();
  }

  fuzz_pos = fuzz_end = NULL;
  return 0;
}
