# Nix flake for BIRD

[`../flake.nix`](../flake.nix) is thin wiring. Each concern lives in its own
module under `nix/`, following the layout of the FRR flake. The flake only
sees **git-tracked** files, so `git add` new or edited files before you
`nix build`.

## Quick start

```sh
nix develop                         # dev shell; prints bird-help
bird-configure && bird-build && bird-check

nix build .#bird                    # hermetic build + `make check`
./result/sbin/bird --version

nix build .#analysis-quick  && cat result/summary.txt   # clang-tidy + cppcheck
nix build .#analysis-deep   && cat result/summary.txt   # every static tool
nix build .#analysis-sanitizers                         # make check under ASan+UBSan
nix build .#fuzz && FUZZ_TIME=600 ./result/bin/run-fuzzers
nix run .#fuzz-campaign -- --hours 12               # long, resumable fuzzing
nix run .#fuzz-coverage -- ~/bird-fuzz              # source coverage of a corpus

nix flake check                     # nix-fmt, deadnix, statix, bird, triage tests, fuzz replay
nix fmt                             # format the Nix files
```

## Targets

| target | what it does |
|---|---|
| `bird` (default) | Builds BIRD (all protocols, pthreads, libssh) and runs `make check`. |
| `compile-db` | Configured, built source tree with `compile_commands.json` (bear over `make all tests`). |
| `analysis-quick` | Runs clang-tidy and cppcheck, then triage. |
| `analysis-standard` | quick, plus flawfinder, scan-build and gcc warnings. |
| `analysis-deep` | standard, plus `gcc -fanalyzer` and semgrep (BIRD rules). |
| `analysis-<tool>` | One tool on its own: `clang-tidy`, `cppcheck`, `flawfinder`, `semgrep`, `clang-analyzer`, `gcc-warnings` or `gcc-analyzer`. |
| `analysis-sanitizers` | ASan, LSan and UBSan build (BIRD's `--enable-asan --enable-ubsan`), running `make check`. |
| `analysis-tsan` | TSan build (clang, `--enable-tsan`), running `make check`. |
| `analysis-valgrind` | Each unit test under valgrind memcheck (`-f`, no fork). |
| `fuzz` | libFuzzer harnesses (BGP, OSPF, Babel, RIP, BFD, RPKI, netlink, CLI, config, flowspec), seed corpora, `bin/run-fuzzers` and `bin/fuzz-campaign` (see `analysis/fuzz/README.md`). |
| `fuzz-run` | Runs each harness for 20 s in the sandbox and collects crashes and reproductions. |
| `fuzz-coverage` | Source-coverage build of the replay binaries and `bin/fuzz-coverage` (llvm-cov report of a corpus). |
| apps `fuzz-campaign`, `fuzz-coverage` | `nix run` entry points for the two scripts above. |
| `bird-configure`, `bird-build`, `bird-check`, `bird-compdb`, `bird-help` | Dev-shell helper commands. |

Each analysis output contains:

- `report.*`, the raw tool output
- `count.txt`, the number of findings
- `summary.txt`

Findings never fail a build. Only a tool that failed to run does.

The aggregates also contain `triage/`. Its `high-confidence.txt` lists
findings that more than one tool flagged, or that a high-signal checker
flagged. It weights findings in security-relevant code higher. That means
the protocol packet parsers, BGP attributes and NLRI, flowspec, RPKI,
netlink and the CLI socket. API-usage lints (flawfinder, alloca, strcpy,
bzero, `-Wpointer-sign`, the semgrep construct rules) only flag a construct.
They appear in `full-report.txt` but never in `high-confidence.txt`, and
several tools flagging the same construct don't count as cross-tool.

## Module map

```
flake.nix                 inputs, per-system wiring, outputs
nix/
  lib.nix                 ctx: pkgs lib packages version configureFlags configureBird
                          scrubStore mkAnalysisDrv
  packages.nix            build inputs, analysis tools, dev tools
  derivation.nix          the BIRD package (also sanitizer variants via args)
  devshell.nix            mkShell + helpers
  shell-commands.nix      bird-* helper scripts (writeShellApplication)
  checks/                 nix-fmt, deadnix, statix
  analysis/
    default.nix           aggregator: mkCompileDbReport, mkSourceReport, mkAggregate
    roots.nix             analysed directories + unit-test regex
    compile-db.nix        bear over the full build
    clang-tidy.nix        bugprone/cert/clang-analyzer/misc checks
    cppcheck.nix          warning/style/performance/portability
    flawfinder.nix        libc hazard scan
    semgrep.nix           semgrep-rules.yaml (wire lengths, bsnprintf, ASSERT) + fixtures
    clang-analyzer.nix    scan-build with BIRD's static-scan checkers + security/taint
    gcc.nix               gcc-warnings, gcc-analyzer
    sanitizers.nix        ASan+UBSan, TSan make-check runs
    valgrind.nix          memcheck over every unit test
    fuzz.nix              fuzzers, fuzz-run, fuzz-replay, fuzz-coverage, campaign wiring
    fuzz/                 harness sources, fuzz.mk, seed generator, campaign / coverage
                          scripts, known-bug suppressions
    triage/               finding parser/scorer (+ test_triage.py)
```

## Notes

- **Configure flags**: `lib.nix` builds every protocol and enables pthreads
  (which BFD needs) and libssh (RPKI over SSH). The analysis and fuzz
  builds also preset `bird_cv_c_lto=no`. With LTO, `-fanalyzer` and the
  sanitizer/fuzzer instrumentation would run at link time.
- **No coccinelle**: unlike FRR, BIRD ships no semantic patches. The
  BIRD-specific rules live in `analysis/semgrep-rules.yaml`.
- **semgrep** comes from `nixpkgs-semgrep` (nixos-26.05), applied as an
  overlay, because the nixos-unstable build of semgrep is broken.
- **Unit tests and sanitizers**: `make check` sends each test's stderr to
  `/dev/null`. Sanitizer reports therefore go to per-process `log_path`
  files, and the pass/fail list comes from the `<test>.ok` stamps.
- **Known-bug suppressions** for fuzzing live in `analysis/fuzz/ubsan.supp`
  and `analysis/fuzz/asan-ignorelist.txt`, or as skips in a harness. Each
  entry names the bug it hides, and `analysis/fuzz/README.md` lists them.
  Drop the entry once that bug is fixed.
