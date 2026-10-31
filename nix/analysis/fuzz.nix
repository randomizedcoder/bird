# nix/analysis/fuzz.nix
#
# libFuzzer harnesses for BIRD's wire-format and config parsers. Targets:
#   fuzzers      one clang build of BIRD (libFuzzer + ASan + UBSan
#                instrumentation), the fuzz_* binaries, plain-main replay_*
#                binaries, seed corpora and a run-fuzzers wrapper
#   fuzz-run     run every harness for runSeconds in the sandbox; saves
#                crash inputs and symbolized reproductions (always exits 0:
#                the crashes are the deliverable, not a build failure)
#   fuzz-replay  flake check: replay the seed corpora through replay_*, so
#                harnesses that stop building or crash on seeds fail CI
#
# Harness sources, the seed generator and fuzz.mk live in ./fuzz; see
# ./fuzz/README.md for what each harness covers.

{ ctx, src }:

let
  inherit (ctx) pkgs lib version;

  stdenv = pkgs.clangStdenv;
  harnessSrc = ./fuzz;
  symbolizer = "${lib.getBin pkgs.llvm}/bin/llvm-symbolizer";

  harnesses = [
    "bgp_msg"
    "bgp_open"
    "flowspec"
    "config"
  ];

  # Largest useful input per harness (BGP extended messages go to 64k).
  maxLen = {
    bgp_msg = 65536;
    bgp_open = 4096;
    flowspec = 4096;
    config = 16384;
  };

  # Seed configs for fuzz_config: BIRD's own example and test configs.
  configSeeds = [
    "doc/bird.conf.example"
    "doc/bird.conf.example2"
    "filter/test.conf"
    "filter/test.conf2"
    "filter/test-reconf-begin.conf"
    "filter/test-reconf-end.conf"
    "proto/aggregator/test.conf"
  ];

  # -fno-sanitize=function: BIRD's resource classes call their free/dump
  # hooks through generic `void (*)(resource *)` pointers (lib/resource.c
  # rfree), so the check fires on every object free and would drown real
  # findings. ASan still covers the memory accesses.
  # asan-ignorelist.txt: known, triaged bugs ASan can't suppress at run time.
  sanFlags = "-fsanitize=address,undefined -fno-sanitize=function";
  sanCflags = "-fsanitize=fuzzer-no-link ${sanFlags} -fsanitize-ignorelist=${./fuzz/asan-ignorelist.txt} -fno-omit-frame-pointer -g -O1";

  fuzzConfigureFlags = [
    "CFLAGS=${sanCflags}"
    "LDFLAGS=${sanFlags}"
  ];

  runFuzzers = pkgs.writeShellApplication {
    name = "run-fuzzers";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.findutils
      pkgs.gnugrep
      pkgs.gnused
    ];
    # Keep going when a harness crashes; the caller reads the workdir.
    bashOptions = [ "nounset" ];
    text = ''
      # Env:
      #   FUZZ_TIME       seconds per harness (default 60)
      #   FUZZ_WORKDIR    output dir (default: mktemp -d)
      #   FUZZ_FORK       libFuzzer -fork jobs per harness (default 1); with
      #                   -fork, crashes are recorded and fuzzing continues
      #   FUZZ_HARNESSES  space-separated subset (default: all)
      #   FUZZ_PARALLEL   1 = run harnesses concurrently (default 1)
      root="$(cd "$(dirname "$0")/.." && pwd)"
      time="''${FUZZ_TIME:-60}"
      workdir="''${FUZZ_WORKDIR:-$(mktemp -d)}"
      fork="''${FUZZ_FORK:-1}"
      parallel="''${FUZZ_PARALLEL:-1}"
      harnesses="''${FUZZ_HARNESSES:-${lib.concatStringsSep " " harnesses}}"

      export ASAN_SYMBOLIZER_PATH="${symbolizer}"
      export UBSAN_SYMBOLIZER_PATH="${symbolizer}"
      export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=1:allocator_may_return_null=1"
      export UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:print_stacktrace=1:symbolize=1:suppressions=$root/share/bird-fuzz/ubsan.supp"

      max_len() {
        case "$1" in
      ${
        lib.concatStrings (lib.mapAttrsToList (n: v: "    ${n}) echo ${toString v} ;;\n") maxLen)
      }    *) echo 4096 ;;
        esac
      }

      run_one() {
        local name="$1" dir="$workdir/$1"
        mkdir -p "$dir/corpus" "$dir/crashes"
        cp -n "$root/share/bird-fuzz/seeds/$name"/* "$dir/corpus/" 2>/dev/null || true
        (cd "$dir" && "$root/bin/fuzz_$name" \
          -max_total_time="$time" \
          -max_len="$(max_len "$name")" \
          -rss_limit_mb=0 \
          -timeout=25 \
          -fork="$fork" \
          -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 \
          -artifact_prefix="$dir/crashes/" \
          -print_final_stats=1 \
          "$dir/corpus" > "$dir/fuzz.log" 2>&1) || true
      }

      echo "Fuzzing for ''${time}s each (fork=$fork); workdir=$workdir"
      for name in $harnesses; do
        if [ "$parallel" = 1 ]; then
          run_one "$name" &
        else
          run_one "$name"
        fi
      done
      wait

      # Symbolized reproduction of every saved input, then a summary.
      summary="$workdir/summary.txt"
      printf '%-12s %8s %8s %10s %s\n' harness corpus crashes execs cov > "$summary"
      for name in $harnesses; do
        dir="$workdir/$name"
        mkdir -p "$dir/repro"
        for c in "$dir"/crashes/*; do
          [ -f "$c" ] || continue
          "$root/bin/fuzz_$name" -runs=1 "$c" > "$dir/repro/$(basename "$c").txt" 2>&1 || true
        done
        crashes=$(find "$dir/crashes" -type f | wc -l)
        corpus=$(find "$dir/corpus" -type f | wc -l)
        # -fork mode: progress lines are "#<total execs>: cov: ..."; no stat:: lines.
        execs=$(grep -aoE '^#[0-9]+: cov:' "$dir/fuzz.log" | tail -1 | tr -dc '0-9' || true)
        cov=$(grep -aoE 'cov: [0-9]+' "$dir/fuzz.log" | tail -1 | sed 's/cov: //' || true)
        printf '%-12s %8s %8s %10s %s\n' "$name" "$corpus" "$crashes" "''${execs:-0}" "''${cov:-?}" >> "$summary"
      done
      cat "$summary"
      echo "$workdir"
    '';
  };

  # Stage 1: BIRD built with fuzzer instrumentation. The output is the built
  # tree (objects, generated sources, Makefile), so harness edits only
  # re-run stage 2. Unlike FRR there are no libraries: the harnesses link
  # the daemon objects directly, as the unit tests do.
  birdFuzzBuild = stdenv.mkDerivation {
    pname = "bird-fuzz-build";
    inherit version src;

    inherit (ctx.packages) nativeBuildInputs buildInputs;

    hardeningDisable = [
      "fortify"
      "fortify3"
    ];
    enableParallelBuilding = true;

    configurePhase = ''
      runHook preConfigure
      ${ctx.configureBird fuzzConfigureFlags}
      runHook postConfigure
    '';

    buildPhase = ''
      runHook preBuild
      make -j"$NIX_BUILD_CORES" all tests
      runHook postBuild
    '';

    installPhase = ''
      mkdir -p $out
      cp -a . $out/
    '';

    dontFixup = true;
    doCheck = false;
  };

  # Stage 2: compile + link the harnesses against the stage-1 tree.
  fuzzers = stdenv.mkDerivation {
    pname = "bird-fuzzers";
    inherit version;
    dontUnpack = true;
    dontConfigure = true;

    nativeBuildInputs = ctx.packages.nativeBuildInputs;
    inherit (ctx.packages) buildInputs;
    hardeningDisable = [
      "fortify"
      "fortify3"
    ];
    enableParallelBuilding = true;

    buildPhase = ''
      runHook preBuild
      # cp -a keeps the store's uniform mtimes, so make sees nothing stale
      # in the BIRD tree and only builds the fuzz targets.
      cp -a ${birdFuzzBuild} tree
      chmod -R u+w tree
      cd tree
      make -j"$NIX_BUILD_CORES" -f Makefile -f ${harnessSrc}/fuzz.mk \
        FUZZ_SRC=${harnessSrc} FUZZ_OUT=fuzz-out fuzz-all
      mkdir -p fuzz-out/seeds
      python3 ${harnessSrc}/gen_seeds.py fuzz-out/seeds
      mkdir -p fuzz-out/seeds/fuzz_config
      for f in ${lib.concatStringsSep " " configSeeds}; do
        cp "$f" "fuzz-out/seeds/fuzz_config/$(echo "$f" | tr / _)"
      done
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p $out/bin $out/share/bird-fuzz/seeds
      for h in ${lib.concatStringsSep " " harnesses}; do
        install -m755 fuzz-out/bin/fuzz_$h $out/bin/
        install -m755 fuzz-out/bin/replay_$h $out/bin/
        cp -r fuzz-out/seeds/fuzz_$h $out/share/bird-fuzz/seeds/$h
      done
      install -m755 ${lib.getExe runFuzzers} $out/bin/run-fuzzers
      cp ${harnessSrc}/README.md ${harnessSrc}/ubsan.supp $out/share/bird-fuzz/
      runHook postInstall
    '';

    dontFixup = true;
    doCheck = false;
  };

  runSeconds = 20;

  fuzz-run = pkgs.stdenv.mkDerivation {
    pname = "bird-fuzz-run";
    inherit version;
    dontUnpack = true;
    dontConfigure = true;

    buildPhase = ''
      runHook preBuild
      export FUZZ_TIME=${toString runSeconds} FUZZ_WORKDIR=$PWD/work FUZZ_PARALLEL=1
      ${fuzzers}/bin/run-fuzzers
      runHook postBuild
    '';

    installPhase = ''
      mkdir -p $out
      cp work/summary.txt $out/
      for d in work/*/; do
        name=$(basename "$d")
        mkdir -p $out/$name
        cp "$d"/fuzz.log $out/$name/
        cp -r "$d"/crashes "$d"/repro $out/$name/ 2>/dev/null || true
      done
      awk 'NR>1 {s+=$3} END {print s+0}' work/summary.txt > $out/count.txt
    '';
  };

  fuzz-replay = pkgs.runCommand "bird-fuzz-replay-${version}" { } ''
    export ASAN_OPTIONS="detect_leaks=0:symbolize=1"
    export ASAN_SYMBOLIZER_PATH="${symbolizer}"
    export UBSAN_OPTIONS="print_stacktrace=1"
    for h in ${lib.concatStringsSep " " harnesses}; do
      echo "=== replay_$h ==="
      ${fuzzers}/bin/replay_$h ${fuzzers}/share/bird-fuzz/seeds/$h
    done
    touch $out
  '';
in
{
  inherit
    birdFuzzBuild
    fuzzers
    fuzz-run
    fuzz-replay
    ;
}
