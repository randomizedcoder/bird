# BIRD fuzz harnesses

Out-of-tree libFuzzer harnesses. They link every BIRD daemon object the
same way the unit tests do (`tests_objs` in `Makefile.in`: everything but
`sysdep/unix/main.o`), so BIRD sources stay unmodified. `../fuzz.nix`
builds them.

```sh
nix build .#fuzz                                    # harnesses + seeds + runner
FUZZ_TIME=1800 FUZZ_FORK=4 ./result/bin/run-fuzzers # long run, outside the sandbox
nix build .#fuzz-run && cat result/summary.txt      # 20 s per harness, sandboxed
nix build .#checks.x86_64-linux.fuzz-replay         # seeds through replay_* builds
```

`run-fuzzers` writes the following into `$FUZZ_WORKDIR/<harness>/`:

- `corpus/`
- `crashes/` (crash, timeout and oom inputs)
- `repro/<input>.txt` (symbolized reproduction)
- `fuzz.log`

It also writes `$FUZZ_WORKDIR/summary.txt`.

To reproduce one input, run `./result/bin/fuzz_<h> <input>` or
`./result/bin/replay_<h> <input>`. Set `FUZZ_VERBOSE=1` to send BIRD's log
(with `debug protocols all`) to stderr.

## Harnesses

Every harness except `fuzz_config` takes its first input byte as a control
byte. The harness source documents what that byte does.

| harness | entry point | reachable from |
|---|---|---|
| `fuzz_bgp_msg` | `bgp_rx()` on an Established eBGP or iBGP session: UPDATE (every attribute decoder, MP_REACH/UNREACH and NLRI for all 13 AFI/SAFIs incl. flowspec, EVPN, VPN, labeled; ADD-PATH; extended next hop), route import into the tables, ROUTE-REFRESH/BoRR/EoRR, NOTIFICATION, raw framing | any configured BGP neighbor once the session is up |
| `fuzz_bgp_open` | `bgp_rx_open()` on a connection in OpenSent: options (incl. RFC 9072 extended), every capability, hold/AS/ID/role checks | any TCP peer that connects to or accepts from a configured neighbor |
| `fuzz_flowspec` | `flow4/6_decode()` + `flow4/6_validate()` oracle, `flow4/6_net_format()`, part iterators, `net_hash()` | BGP flowspec NLRI (both AFIs) |
| `fuzz_config` | `config_parse()`: lexer, bison grammar, filter compiler, protocol postconfig | `birdc configure`, included config files |

### How the BGP harnesses get a session

`fuzz_bgp_common.h` runs BIRD's real configuration and startup path, with
two `multihop` BGP protocols (`peer_e`: eBGP, `peer_i`: iBGP, peer is a
route reflector client) that have a channel for every AFI/SAFI. Only the
socket layer is stubbed, with `-Wl,--wrap`: `sk_open()` allocates the
buffers without a descriptor, and `sk_send()` reports success. The harness
fires the connect timer and the socket's connected hook. It then feeds a
peer OPEN, carrying every capability BIRD implements, and a KEEPALIVE.
Both sessions reach Established with all 13 channels up, exactly as with a
real peer.

`bgp_error()` and the close paths called from `packets.c` are wrapped as
well. They record the error and mark the connection closed, which stops
`bgp_rx()` the way the real ones do. The session is kept, so every input
starts from Established. The NOTIFICATION data an error points at is still
read, so a bad pointer or length there is caught. `--wrap` only redirects
calls between objects, so `bgp.c`'s own internal calls are unaffected.

## Seeds

`gen_seeds.py` hand-builds well-formed seeds for the BGP and flowspec
harnesses. They cover:

- UPDATEs for every AFI/SAFI, every attribute BIRD knows, AS4 and iBGP
  attributes, and the RFC 8277 withdraw label
- ROUTE-REFRESH subtypes
- OPENs in both option formats

`fuzz_config` starts from BIRD's own example and unit-test configs.

## Adding a harness

1. Add `fuzz_<name>.c`, which defines `LLVMFuzzerTestOneInput`. Put one-time
   setup behind `FUZZ_ONCE` (`fuzz_bird_init()` for a BIRD environment).
2. In `fuzz.mk`, add the harness to `FUZZERS` and give it a
   `fuzz_<name>_LDFLAGS` line (wraps, if any).
3. In `../fuzz.nix`, add it to `harnesses` and `maxLen`.
4. Add seeds to `gen_seeds.py`.

## Not fuzzed yet

The following need interface and neighbor state that the harnesses don't
fake yet:

- OSPFv2/v3 packets and LSAs (`proto/ospf/packet.c`, `lsupd.c`, ...)
- Babel (`proto/babel/packets.c`)
- RIP (`proto/rip/packets.c`), RAdv, BFD
- RPKI-to-router PDUs (`proto/rpki/packets.c`)
- netlink messages from the kernel (`sysdep/linux/netlink.c`)
- CLI commands over the control socket (`cli_parse()` runs the commands)
