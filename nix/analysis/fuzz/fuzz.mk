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

# Objects a harness compiles in itself (it #includes the .c file to reach
# static functions), so they are left out of its link.
fuzz_netlink_EXCLUDE = $(objdir)/sysdep/linux/netlink.o
FUZZ_LIBS = $(LIBS) $(DAEMON_LIBS)

# Every harness: the real sysdep_preconfig() lives in main.o, which is not
# linked; birdtest.c's stub would leave the config lists uninitialized.
# times_update(): the virtual clock in fuzz_bird.h. rf_open(): inputs
# never create files (fuzz_bird.h).
FUZZ_WRAP = -Wl,--wrap=sysdep_preconfig,--wrap=times_update,--wrap=rf_open

# Socket layer stubs (fuzz_sock.h), for every harness that opens sockets.
FUZZ_SOCK_WRAPS = -Wl,--wrap=sk_open,--wrap=sk_send,--wrap=sk_send_to \
	-Wl,--wrap=sk_setup_multicast,--wrap=sk_join_group,--wrap=sk_leave_group \
	-Wl,--wrap=sk_setup_broadcast,--wrap=sk_set_ttl,--wrap=sk_set_min_ttl \
	-Wl,--wrap=sk_set_ipv6_checksum

# Fake interfaces (fuzz_iface.h): no netlink sockets, no host interface scan.
FUZZ_IFACE_WRAPS = -Wl,--wrap=kif_sys_start,--wrap=kif_do_scan

# Session-preserving error paths (fuzz_bgp_common.h).
BGP_WRAP = $(FUZZ_SOCK_WRAPS) -Wl,--wrap=bgp_error \
	-Wl,--wrap=bgp_conn_enter_close_state,--wrap=bgp_conn_enter_idle_state \
	-Wl,--wrap=bgp_stop

fuzz_bgp_msg_LDFLAGS = $(BGP_WRAP)
fuzz_bgp_open_LDFLAGS = $(BGP_WRAP)
fuzz_flowspec_LDFLAGS =
fuzz_config_LDFLAGS =
fuzz_babel_LDFLAGS = $(FUZZ_SOCK_WRAPS) $(FUZZ_IFACE_WRAPS)
fuzz_rip_LDFLAGS = $(FUZZ_SOCK_WRAPS) $(FUZZ_IFACE_WRAPS)
fuzz_rpki_LDFLAGS = $(FUZZ_SOCK_WRAPS) -Wl,--wrap=rpki_cache_change_state
fuzz_netlink_LDFLAGS = $(FUZZ_IFACE_WRAPS) -Wl,--wrap=krt_sys_start,--wrap=krt_do_scan
fuzz_ospf_LDFLAGS = $(FUZZ_SOCK_WRAPS) $(FUZZ_IFACE_WRAPS)
fuzz_ospf_lsa_LDFLAGS = $(FUZZ_SOCK_WRAPS) $(FUZZ_IFACE_WRAPS)
fuzz_bfd_LDFLAGS = $(FUZZ_SOCK_WRAPS) $(FUZZ_IFACE_WRAPS) -Wl,--wrap=birdloop_start
fuzz_cli_LDFLAGS = $(FUZZ_IFACE_WRAPS) -Wl,--wrap=cli_get_command,--wrap=cli_write_trigger \
	-Wl,--wrap=cmd_dump_file,--wrap=mrt_dump_cmd

# fuzz.nix passes the list; this default keeps a plain `make -f` working.
FUZZERS ?= fuzz_bgp_msg fuzz_bgp_open fuzz_flowspec fuzz_config fuzz_babel fuzz_rip \
	fuzz_rpki fuzz_netlink fuzz_cli fuzz_ospf fuzz_ospf_lsa fuzz_bfd

FUZZ_BINS = $(addprefix $(FUZZ_OUT)/bin/,$(FUZZERS))
REPLAY_BINS = $(addprefix $(FUZZ_OUT)/bin/replay_,$(patsubst fuzz_%,%,$(FUZZERS)))

.PHONY: fuzz-all replay-all
fuzz-all: $(FUZZ_BINS) $(REPLAY_BINS) $(FUZZ_OUT)/bird.dict

# Coverage build (fuzz.nix fuzz-coverage): plain-main replay binaries only.
replay-all: $(REPLAY_BINS)

# libFuzzer dictionary for the text harnesses (cli, config): every keyword
# of the config and CLI grammar, from the generated lexer table.
$(FUZZ_OUT)/bird.dict: $(objdir)/conf/keywords.h
	@mkdir -p $(@D)
	sed -n 's/^{ "\([^"]*\)".*/"\1"/p' $< | sort -u > $@

# Keep harness objects between runs (they are pattern-rule intermediates).
.SECONDARY:

$(FUZZ_OUT)/obj/birdtest_nomain.o: $(srcdir)/test/birdtest.c | prepare
	@mkdir -p $(@D)
	$(CC) $(FUZZ_CFLAGS) -Dmain=birdtest_main -c -o $@ $<

$(FUZZ_OUT)/obj/%.o: $(FUZZ_SRC)/%.c $(wildcard $(FUZZ_SRC)/*.h) | prepare
	@mkdir -p $(@D)
	$(CC) $(FUZZ_CFLAGS) -c -o $@ $<

# libFuzzer binaries
$(FUZZ_OUT)/bin/fuzz_%: $(FUZZ_OUT)/obj/fuzz_%.o $(FUZZ_OBJS)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -fsanitize=fuzzer $(FUZZ_WRAP) $(fuzz_$*_LDFLAGS) -o $@ \
		$(filter-out $(fuzz_$*_EXCLUDE),$^) $(FUZZ_LIBS)

# plain-main replay binaries over the same objects
$(FUZZ_OUT)/bin/replay_%: $(FUZZ_OUT)/obj/fuzz_%.o $(FUZZ_OUT)/obj/replay_main.o $(FUZZ_OBJS)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $(FUZZ_WRAP) $(fuzz_$*_LDFLAGS) -o $@ \
		$(filter-out $(fuzz_$*_EXCLUDE),$^) $(FUZZ_LIBS)
