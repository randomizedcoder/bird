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
#include "lib/timer.h"
#include "conf/conf.h"
#include "nest/protocol.h"
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

/* Virtual clock: fuzz.mk links every harness with --wrap=times_update, so
 * BIRD's notion of now (current_time(), timer expiry) only moves when a
 * harness calls fuzz_advance(). Inputs replay deterministically, and the
 * harnesses can still reach timer-driven code (hold / dead / retransmit
 * timers, LSA aging, SPF scheduling, rate limits) by advancing it. */
struct timeloop;
void __wrap_times_update(struct timeloop *loop);

static btime fuzz_clock;

void
__wrap_times_update(struct timeloop *loop)
{
  if (fuzz_clock < loop->last_time)
    fuzz_clock = loop->last_time;

  loop->last_time = fuzz_clock;
  loop->real_time = 0;
}

static inline void fuzz_pump(void);

/* Move the clock forward by dt, then run the timers that are due and the
 * events they queue, as one main loop iteration would. */
static inline void
fuzz_advance(btime dt)
{
  if (fuzz_clock < main_timeloop.last_time)
    fuzz_clock = main_timeloop.last_time;

  fuzz_clock += dt;
  timers_fire(&main_timeloop);
  fuzz_pump();
}

/* fuzz_advance() by an input byte: 0.1 s to 25.6 s. */
static inline void
fuzz_advance_byte(uint8_t b)
{
  fuzz_advance((b + 1) * 100 MS);
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

/* The configured instance `name` of protocol `pr`; aborts if missing. */
extern list proto_list;

/* Files: fuzz.mk links every harness with --wrap=rf_open, so whatever file
 * an input names in `log "..."`, `mrtdump "..."` or an MRT dump, nothing
 * is created; the file is /dev/null. */
struct rfile;
struct rfile *__real_rf_open(struct pool *p, const char *name, const char *mode);
struct rfile *__wrap_rf_open(struct pool *p, const char *name, const char *mode);

struct rfile *
__wrap_rf_open(struct pool *p, const char *name UNUSED, const char *mode)
{
  return __real_rf_open(p, "/dev/null", mode);
}

static inline struct proto *
fuzz_proto_find(struct protocol *pr, const char *name)
{
  struct proto *p;

  WALK_LIST(p, proto_list)
    if ((p->proto == pr) && !strcmp(p->name, name))
      return p;

  fprintf(stderr, "fuzz: protocol %s not found\n", name);
  abort();
}

/* bt_init + bt_bird_init, then parse and commit `cfg` (if non-NULL),
 * prefixed with fuzz_log_config(). */
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
    const char *log = fuzz_log_config();
    char *full = malloc(strlen(log) + strlen(cfg) + 1);

    strcpy(full, log);
    strcat(full, cfg);
    if (!bt_config_parse(full))
    {
      fprintf(stderr, "fuzz: harness configuration failed to parse\n");
      abort();
    }
    fuzz_pump();
  }
}

#endif
