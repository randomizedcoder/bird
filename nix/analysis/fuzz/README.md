# BIRD fuzz harnesses

Out-of-tree libFuzzer harnesses. They link every BIRD daemon object the
same way the unit tests do (`tests_objs` in `Makefile.in`: everything but
`sysdep/unix/main.o`), so BIRD sources stay unmodified. `../fuzz.nix`
builds them.

```sh
nix build .#fuzz                                    # harnesses + seeds + runners
nix run .#fuzz-campaign -- --hours 12               # long, resumable campaign
nix run .#fuzz-coverage -- ~/bird-fuzz              # what the corpus reaches
FUZZ_TIME=300 ./result/bin/run-fuzzers              # short run of every harness
nix build .#fuzz-run && cat result/summary.txt      # 20 s per harness, sandboxed
nix build .#checks.x86_64-linux.fuzz-replay         # seeds through replay_* builds
```

To reproduce one input, run `./result/bin/fuzz_<h> <input>` or
`./result/bin/replay_<h> <input>`. Set `FUZZ_VERBOSE=1` to send BIRD's log
(with `debug protocols all`) to stderr; `fuzz_cli` also echoes the commands
and their output.

## Harnesses

Every harness except `fuzz_config` takes its first input byte as a control
byte. The harness source documents what that byte does.

| harness | entry point | reachable from |
|---|---|---|
| `fuzz_bgp_msg` | `bgp_rx()` on an Established eBGP or iBGP session: UPDATE (every attribute decoder, MP_REACH/UNREACH and NLRI for all 13 AFI/SAFIs incl. flowspec, EVPN, VPN, labeled; ADD-PATH; extended next hop), route import into the tables, ROUTE-REFRESH/BoRR/EoRR, NOTIFICATION, raw framing | any configured BGP neighbor once the session is up |
| `fuzz_bgp_open` | `bgp_rx_open()` on a connection in OpenSent: options (incl. RFC 9072 extended), every capability, hold/AS/ID/role checks | any TCP peer that connects to or accepts from a configured neighbor |
| `fuzz_flowspec` | `flow4/6_decode()` + `flow4/6_validate()` oracle, `flow4/6_net_format()`, part iterators, `net_hash()` | BGP flowspec NLRI (both AFIs) |
| `fuzz_config` | `config_parse()`: lexer, bison grammar, filter compiler, protocol postconfig | `birdc configure`, included config files |
| `fuzz_ospf` | `ospf_rx_hook()` on four point-to-point interfaces (OSPFv2 and v3; backbone, NSSA, stub) with a Full neighbour: Hello, DBDES, LSR, LSU (`lsa_validate()`, LSDB install, flooding), LSAck; with the clock moving, SPF, route import, LSA origination and aging | any host on an OSPF link |
| `fuzz_ospf_lsa` | `lsa_validate()` and every per-type validator, then `lsa_walk_rt()`, `lsa_parse_sum_*()`, `lsa_parse_ext()`, `lsa_get_tlv()` | any OSPF neighbour (LSUs), or anyone it floods for |
| `fuzz_babel` | `babel_rx_hook()`, `babel_process_packet()`, every TLV and sub-TLV reader, the MAC / PC / challenge trailer (permissive mode), the TLV handlers, route selection and import, SADR | any host on a Babel link |
| `fuzz_rip` | `rip_rx_hook()`, plaintext and cryptographic authentication, RFC 2091 demand circuit messages, request / response / ack handling and route import, RIPv2 and RIPng | any host on a RIP link |
| `fuzz_bfd` | `bfd_rx_hook()`, simple / keyed / meticulous MD5 and SHA1 authentication, `bfd_session_process_ctl()` (state machine, poll / final) for single-hop IPv4 and IPv6 and multihop sessions | anyone who can send UDP to the BFD ports |
| `fuzz_rpki` | `rpki_rx_hook()` framing, version negotiation, every PDU type incl. Error Report and ASPA, ROA / ASPA import into the tables | the RPKI cache, or anyone able to inject into its TCP session |
| `fuzz_netlink` | `nl_async_msg()` (link incl. VXLAN / VRF data, address, route, bridge FDB) and the route table scan (`nl_parse_route()`, multipath, metrics, MPLS), import through the kernel protocols | the kernel, i.e. any process that can change interfaces, addresses or routes in BIRD's network namespace |
| `fuzz_cli` | `cli_command()` / `cli_parse()`: every `show` command and its continuation, `eval`, `echo`, `debug`, `dump`, `mrt dump`, protocol enable / disable / restart / reload, in restricted and unrestricted mode | anyone allowed to connect to `bird.ctl` or a restricted CLI socket |

### Shared machinery

- `fuzz_bird.h`: `fuzz_bird_init()` (BIRD's real startup and config
  commit, with no main loop), `fuzz_pump()` (runs the event queues),
  `fuzz_proto_find()`, and the **virtual clock**. Every harness links with
  `-Wl,--wrap=times_update`, so `current_time()` only moves when a harness
  calls `fuzz_advance()`, which then fires the timers that are due. Inputs
  replay deterministically, and timer-driven code (hold, dead and
  retransmit timers, LSA aging, SPF scheduling, rate limits) is still
  reachable.
- Also in `fuzz_bird.h`: `rf_open()` is wrapped to open `/dev/null`, so a
  `log "..."` or `mrtdump "..."` in a fuzzed config or CLI command never
  creates a file, wherever its path points.
- `fuzz_sock.h`: the socket layer, stubbed with `-Wl,--wrap`. `sk_open()`
  allocates the buffers and opens no descriptor, the send and multicast
  helpers succeed, and `fuzz_sk_feed()` delivers a datagram with the
  addresses, ports, interface and TTL the rx hooks check.
- `fuzz_iface.h`: fake interfaces `fz0`, `fz1`, ... (10.0.*n*.1/24,
  2001:db8:0:*n*::1/64, fe80::1/64), reported the way an async netlink
  update would. The device protocol runs, but its kernel scan is stubbed.

`--wrap` only redirects calls between objects, so a protocol's internal
calls are unaffected.

### How the BGP harnesses get a session

`fuzz_bgp_common.h` runs BIRD's real configuration and startup path, with
two `multihop` BGP protocols (`peer_e`: eBGP, `peer_i`: iBGP, peer is a
route reflector client) that have a channel for every AFI/SAFI. The
harness fires the connect timer and the socket's connected hook. It then
feeds a peer OPEN, carrying every capability BIRD implements, and a
KEEPALIVE. Both sessions reach Established with all 13 channels up, exactly
as with a real peer.

`bgp_error()` and the close paths called from `packets.c` are wrapped as
well. They record the error and mark the connection closed, which stops
`bgp_rx()` the way the real ones do. The session is kept, so every input
starts from Established. The NOTIFICATION data an error points at is still
read, so a bad pointer or length there is caught.

### How the other protocols get their state

- **OSPF**: the harness sends a Hello listing BIRD's router ID, then a DBDES
  exchange as master, until the neighbour is Full. It repeats this whenever
  an input drops the neighbour below Exchange (LSR, LSU and LSAck need
  Exchange or later). It writes the OSPF header, the OSPFv2 checksum and
  each LSA's Fletcher checksum, unless the control byte asks for raw
  input, and advances the clock 1 s per input (past MinLSArrival).
- **RPKI**: the protocol connects over the stubbed socket and sends its
  Reset Query. `rpki_cache_change_state()` is wrapped, so error states
  are recorded instead of tearing the cache down. Each input starts from
  a new or a synchronized session.
- **BFD**: `birdloop_start()` is wrapped, so the BFD thread never starts.
  The harness calls the rx hook while holding the BFD loop. Sessions come
  from configured neighbours; BFD's own timers don't run.
- **netlink**: the harness `#include`s `netlink.c` (its parsers are
  static) and `fuzz.mk` leaves `netlink.o` out of that link. No netlink
  socket opens. The requests BIRD sends back, such as deleting a stale
  route of its own, are acknowledged as the kernel would.
- **CLI**: `cli_get_command()` and `cli_write_trigger()` are wrapped
  (input lines in, output read and freed). `dump` writes to a scratch file
  that is deleted again, and `mrt dump` writes to `/dev/null`, whatever
  file the command names.

## Long campaigns: `fuzz-campaign`

```sh
nix run .#fuzz-campaign -- --hours 12 --jobs 22 --workdir ~/bird-fuzz
# detached, survives logout:
systemd-run --user --unit bird-fuzz -p RuntimeMaxSec=13h \
  "$(nix build .#fuzz --print-out-paths)/bin/fuzz-campaign" --hours 12
journalctl --user -u bird-fuzz -f
cat ~/bird-fuzz/status.txt
```

- **Jobs:** `--jobs` (default `nproc - 2`) is split across the harnesses by
  weight (`harnessMeta` in `../fuzz.nix`). Each harness runs libFuzzer
  `-fork=N` with crashes, timeouts and OOMs recorded rather than fatal,
  under `nice`, with a 4 GB RSS and single-allocation cap (`--rss-mb`).
- **Resumable:** `DIR/<harness>/corpus` is kept. Run the same command
  again after an interruption, or for another round, and it continues from
  the coverage already reached.
- **While running:** `DIR/status.txt` shows executions, coverage, corpus
  size, executions per second and crash files per harness, updated every
  `--status-minutes` (15). Each update also appends to `DIR/history.csv`.
  The campaign stops early when the file system has less than
  `--min-free-gb` (10) free.
- **At the end, also after Ctrl-C or SIGTERM:**
  - every saved input is reproduced into `DIR/<harness>/repro/`
  - crashes are grouped by sanitizer summary and the top three BIRD stack
    frames into `DIR/<harness>/unique.txt`
  - each corpus is minimized (`-merge=1`, skip with `--no-merge`)
  - `DIR/summary.txt` gets one line per harness

## Targeted campaigns: `fuzz-plateau`

```sh
# only the harnesses that cover what this branch changed since master
nix run .#fuzz-plateau -- --changed master
# every harness, each stopped at its own plateau
nix run .#fuzz-plateau -- --workdir ~/bird-fuzz
```

`fuzz-plateau` is `fuzz-campaign --hours 3 --plateau-minutes 30`, and
takes the same options; later ones win.

- **Plateau stop:** a harness whose coverage (`cov`, or the finer libFuzzer
  features with `--plateau-metric ft`) has not grown for
  `--plateau-minutes` is stopped. Its jobs go to the heaviest harness still
  running, which is restarted with them on the same corpus. The campaign
  ends when every harness has stopped, or at `--hours`, and then
  reproduces, deduplicates and merges as above. `DIR/campaign.txt` logs
  each stop and handover, and `status.txt` shows each harness's state.
- **Why:** in the first 12-hour campaign, `ospf_lsa`, `rip` and `flowspec`
  reached 99% of their final coverage in 15 minutes, `babel`, `rpki` and
  `bfd` within 90, and `ospf` in two hours. Only `bgp_msg`, `bgp_open`,
  `cli` and `config` were still growing after eight hours.
- **`--changed REF`:** keeps the harnesses that cover a file changed since
  the merge base of `REF` and `HEAD` (uncommitted changes included), in the
  git checkout of the current directory. Each harness covers the shared
  code (`corePaths` in `../fuzz.nix`: `lib/`, `nest/`, `conf/`, `filter/`,
  `sysdep/unix/` and the harness headers), its own `fuzz_<name>.c`, and
  its `paths`. Run it from the checkout the fuzzers were built from, so
  the binaries match the changes.
- A plateau is not proof of no bugs: the first campaign's netlink crash
  came after eight hours, with coverage almost flat. For a release, or
  after big changes, run `fuzz-campaign` for longer.

## Coverage: `fuzz-coverage`

```sh
nix run .#fuzz-coverage -- ~/bird-fuzz            # writes ~/bird-fuzz/coverage/
xdg-open ~/bird-fuzz/coverage/html/index.html
```

`fuzz-coverage` replays each harness's corpus through a separate build of
the replay binaries with clang source-coverage instrumentation (no
sanitizers). Harnesses without a corpus use their seeds. It writes:

- `summary.txt`: per-file coverage over all harnesses
- `<harness>.txt`: the same for one harness
- `functions.txt`: functions never executed, by file
- `html/`: annotated sources

`fuzz_netlink` compiles `netlink.c` itself, so its coverage appears under
`tree/sysdep/linux/netlink.c`. The `source/` copy is the unused one linked
into the other harnesses.

## Seeds and dictionary

`gen_seeds.py` hand-builds well-formed seeds for every harness except
`fuzz_config`:

- BGP UPDATEs for every AFI/SAFI and attribute, ROUTE-REFRESH, OPENs
- OSPF Hello, DBDES, LSR, LSAck and LSUs with every LSA type for both
  versions; `fuzz_ospf_lsa` gets each LSA on its own
- Babel TLVs incl. prefix compression, SADR, MAC trailers and challenges
- RIPv2, RIPng, plaintext and cryptographic auth, demand circuit messages
- BFD control packets for each session state and auth type
- RPKI-RTR PDUs for versions 0 to 2, incl. ASPA and Error Report
- netlink link, address and route messages (multipath, metrics, MPLS,
  VXLAN, VRF)
- CLI command sets

`fuzz_config` starts from BIRD's own example and unit-test configs.
`fuzz.mk` generates `bird.dict` from the grammar's keyword table, and
`fuzz_cli` and `fuzz_config` fuzz with it.

## Known findings

These stop a fuzzer on every hit, so each is suppressed in `ubsan.supp`
or skipped by its harness, with the reason next to it. Remove the entry
once the bug is fixed.

- **`nl_parse_addr4()` / `nl_parse_addr6()`:** log "Invalid prefix
  length", then use it anyway: `u32_mkmask(33)` shifts by −1 (UBSan).
  Skipped in `fuzz_netlink.c`.
- **`nl_parse_multipath()`, zero `rtnh_len`:** never advances past a dead
  next hop with `rtnh_len == 0`, so it loops forever. Skipped in
  `fuzz_netlink.c`.
- **`nl_parse_multipath()`, unaligned `rtnh_len`:** in an unaligned
  `RTA_MULTIPATH` payload, the length wraps and the loop reads past the
  message (ASan heap-buffer-overflow). Skipped in `fuzz_netlink.c`.
- **`rip_check_authentication()`:** the auth trailer sits at a
  packet-controlled offset, so its fields can be accessed misaligned
  before the MAC check. Suppressed for `proto/rip/packets.c`.
- **`lib/net.h` accessors:** a typed `net_addr_<type>` is read through the
  generic `net_addr *`. This is a BIRD idiom, not a memory bug. Suppressed
  as `object-size:lib/net.h`.

The netlink findings need a malformed message from the kernel.
`nl_async_hook()` drops anything not sent by the kernel.

## Adding a harness

1. Add `fuzz_<name>.c`, which defines `LLVMFuzzerTestOneInput`. Put one-time
   setup behind `FUZZ_ONCE` (`fuzz_bird_init()` for a BIRD environment,
   `fuzz_iface_add()` for interfaces).
2. In `fuzz.mk`, give it a `fuzz_<name>_LDFLAGS` line: `$(FUZZ_SOCK_WRAPS)`
   if it opens sockets, `$(FUZZ_IFACE_WRAPS)` if it uses fake interfaces,
   and any wraps of its own.
3. In `../fuzz.nix`, add it to `harnessMeta`.
4. Add seeds to `gen_seeds.py`.
