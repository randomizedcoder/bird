# Link the out-of-tree fuzz harnesses against a BIRD build tree.
# Used as:  make -f Makefile -f nix/analysis/fuzz/fuzz.mk FUZZ_SRC=... fuzz-all
# so the harnesses compile with exactly BIRD's own CFLAGS and link the same
# objects the unit tests do (Makefile.in: tests_objs = every daemon object
# except sysdep/unix/main.o, plus test/birdtest.o and test/bt-utils.o).
# birdtest.c is rebuilt with its main() renamed; its daemon stubs stay.
#
# Can be freely distributed and used under the terms of the GNU GPL.

FUZZ_SRC ?= nix/analysis/fuzz
FUZZ_OUT ?= fuzz-out

FUZZ_CFLAGS = $(CFLAGS) -I$(FUZZ_SRC) -Wno-unused-parameter -Wno-missing-field-initializers
FUZZ_OBJS = $(FUZZ_OUT)/obj/birdtest_nomain.o \
	$(filter-out $(objdir)/test/birdtest.o,$(tests_objs))
FUZZ_LIBS = $(LIBS) $(DAEMON_LIBS)

# Every harness: the real sysdep_preconfig() lives in main.o, which is not
# linked; birdtest.c's stub would leave the config lists uninitialized.
FUZZ_WRAP = -Wl,--wrap=sysdep_preconfig

# Socket layer stubs and session-preserving error paths (fuzz_bgp_common.h).
BGP_WRAP = -Wl,--wrap=sk_open,--wrap=sk_send,--wrap=bgp_error \
	-Wl,--wrap=bgp_conn_enter_close_state,--wrap=bgp_conn_enter_idle_state \
	-Wl,--wrap=bgp_stop

fuzz_bgp_msg_LDFLAGS = $(BGP_WRAP)
fuzz_bgp_open_LDFLAGS = $(BGP_WRAP)
fuzz_flowspec_LDFLAGS =
fuzz_config_LDFLAGS =

FUZZERS = fuzz_bgp_msg fuzz_bgp_open fuzz_flowspec fuzz_config

FUZZ_BINS = $(addprefix $(FUZZ_OUT)/bin/,$(FUZZERS))
REPLAY_BINS = $(addprefix $(FUZZ_OUT)/bin/replay_,$(patsubst fuzz_%,%,$(FUZZERS)))

.PHONY: fuzz-all
fuzz-all: $(FUZZ_BINS) $(REPLAY_BINS)

$(FUZZ_OUT)/obj/birdtest_nomain.o: $(srcdir)/test/birdtest.c | prepare
	@mkdir -p $(@D)
	$(CC) $(FUZZ_CFLAGS) -Dmain=birdtest_main -c -o $@ $<

$(FUZZ_OUT)/obj/%.o: $(FUZZ_SRC)/%.c $(wildcard $(FUZZ_SRC)/*.h) | prepare
	@mkdir -p $(@D)
	$(CC) $(FUZZ_CFLAGS) -c -o $@ $<

# libFuzzer binaries
$(FUZZ_OUT)/bin/fuzz_%: $(FUZZ_OUT)/obj/fuzz_%.o $(FUZZ_OBJS)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -fsanitize=fuzzer $(FUZZ_WRAP) $(fuzz_$*_LDFLAGS) -o $@ $^ $(FUZZ_LIBS)

# plain-main replay binaries over the same objects
$(FUZZ_OUT)/bin/replay_%: $(FUZZ_OUT)/obj/fuzz_%.o $(FUZZ_OUT)/obj/replay_main.o $(FUZZ_OBJS)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $(FUZZ_WRAP) $(fuzz_$*_LDFLAGS) -o $@ $^ $(FUZZ_LIBS)
