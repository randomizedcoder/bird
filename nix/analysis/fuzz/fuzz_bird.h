/*
 *	Shared setup for the out-of-tree BIRD libFuzzer harnesses.
 *
 *	The harnesses link every daemon object except sysdep/unix/main.o,
 *	exactly like the unit tests (Makefile.in tests_objs), plus
 *	test/birdtest.c compiled with -Dmain=birdtest_main for its daemon
 *	stubs (cmd_reconfig, sysdep_commit, ...). fuzz_bird_init() is
 *	bt_init() + bt_bird_init() + an optional config commit, with no
 *	main loop: fuzz_pump() runs the event queues instead.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_NIX_FUZZ_BIRD_H_
#define _BIRD_NIX_FUZZ_BIRD_H_

#include <stdlib.h>

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "nest/bird.h"
#include "lib/event.h"
#include "conf/conf.h"
#include "sysdep/unix/unix.h"

#include "fuzz_harness.h"

/* Logging: to stderr with protocol tracing when FUZZ_VERBOSE is set,
 * otherwise to /dev/null (messages are still formatted, so the format
 * paths stay covered). */
void log_init_debug(char *);
void log_switch(int initial, list *l, const char *);

static inline int
fuzz_verbose(void)
{
  return getenv("FUZZ_VERBOSE") != NULL;
}

static inline const char *
fuzz_log_config(void)
{
  return fuzz_verbose() ? "debug protocols all;\n" : "";
}

/* birdtest.c stubs sysdep_preconfig() out, which leaves the config's log
 * list uninitialized: any `log` statement would then crash in add_tail().
 * fuzz.mk links every harness with -Wl,--wrap=sysdep_preconfig, so
 * config_parse() gets this copy of sysdep/unix/main.c's version instead,
 * minus the iproute2 tables (they read the host's /etc) and the static
 * cli_preconfig() (a no-op without a main control socket). */
void __wrap_sysdep_preconfig(struct config *c);

void
__wrap_sysdep_preconfig(struct config *c)
{
  init_list(&c->logfiles);

  c->latency_limit = UNIX_DEFAULT_LATENCY_LIMIT;
  c->watchdog_warning = UNIX_DEFAULT_WATCHDOG_WARNING;
}

/* Run queued events (protocol state changes, table pruning, TX kicks) until
 * the queues drain or a bound is hit; events may reschedule themselves. */
static inline void
fuzz_pump(void)
{
  for (int i = 0; i < 256; i++)
  {
    if (EMPTY_LIST(global_event_list) && EMPTY_LIST(global_work_list))
      return;
    ev_run_list(&global_event_list);
    ev_run_list(&global_work_list);
  }
}

/* bt_init + bt_bird_init, then parse and commit `cfg` (if non-NULL). */
static inline void
fuzz_bird_init(const char *cfg)
{
  char *argv[] = { "fuzz", NULL };

  bt_init(1, argv);
  bt_bird_init();

  if (!fuzz_verbose())
  {
    log_init_debug("/dev/null");
    log_switch(0, NULL, NULL);
  }

  if (cfg)
  {
    if (!bt_config_parse(cfg))
    {
      fprintf(stderr, "fuzz: harness configuration failed to parse\n");
      abort();
    }
    fuzz_pump();
  }
}

#endif
