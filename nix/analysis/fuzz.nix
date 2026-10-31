# nix/analysis/fuzz.nix
#
# libFuzzer harnesses for BIRD's wire-format, protocol, kernel, CLI and
# config parsers. Targets:
#   fuzzers        one clang build of BIRD (libFuzzer + ASan + UBSan
#                  instrumentation), the fuzz_* binaries, plain-main replay_*
#                  binaries, seed corpora, the keyword dictionary, and the
#                  run-fuzzers (short runs) and fuzz-campaign (long,
#                  resumable runs) wrappers
#   fuzz-run       run every harness for runSeconds in the sandbox; saves
#                  crash inputs and symbolized reproductions (always exits 0:
#                  the crashes are the deliverable, not a build failure)
#   fuzz-replay    flake check: replay the seed corpora through replay_*
#                  with the sanitizers halting on error, so harnesses that
#                  stop building or crash on seeds fail CI
#   fuzz-coverage  a source-coverage build of the replay_* binaries and the
#                  fuzz-coverage report script (llvm-cov over a corpus)
#
# Harness sources, the seed generator and fuzz.mk live in ./fuzz; see
# ./fuzz/README.md for what each harness covers.

{ ctx, src }:

let
  inherit (ctx) pkgs lib version;

  stdenv = pkgs.clangStdenv;
  harnessSrc = ./fuzz;
  symbolizer = "${lib.getBin pkgs.llvm}/bin/llvm-symbolizer";

  # Per harness: the largest useful input (BGP extended messages and RPKI
  # PDUs go to 64k), the campaign weight (share of fuzz-campaign jobs; more
  # for the larger attack surfaces), and whether it gets the keyword
  # dictionary (text inputs).
  harnessMeta = {
    bgp_msg = {
      maxLen = 65536;
      weight = 3;
    };
    bgp_open = {
      maxLen = 4096;
      weight = 1;
    };
    flowspec = {
      maxLen = 4096;
      weight = 1;
    };
    config = {
      maxLen = 16384;
      weight = 2;
      dict = true;
    };
    babel = {
      maxLen = 4096;
      weight = 2;
    };
    rip = {
      maxLen = 4096;
      weight = 2;
    };
    rpki = {
      maxLen = 65536;
      weight = 2;
    };
    netlink = {
      maxLen = 32768;
      weight = 2;
    };
    cli = {
      maxLen = 16384;
      weight = 2;
      dict = true;
    };
    ospf = {
      maxLen = 8192;
      weight = 3;
    };
    ospf_lsa = {
      maxLen = 4096;
      weight = 1;
    };
    bfd = {
      maxLen = 512;
      weight = 1;
    };
  };

  harnesses = lib.attrNames harnessMeta;
  fuzzerNames = lib.concatMapStringsSep " " (h: "fuzz_${h}") harnesses;

  # Shell prelude for the wrapper scripts: the package root, the symbolizer,
  # the harness list and per-harness lookups, then fuzz-common.sh.
  shellCase = fn: default: attr: ''
    ${fn}() {
      case "$1" in
    ${
      lib.concatStrings (
        lib.mapAttrsToList (n: m: "    ${n}) echo \"${toString (attr m)}\" ;;\n") harnessMeta
      )
    }    *) echo "${default}" ;;
      esac
    }
  '';

  scriptPrelude = ''
    root="$(cd "$(dirname "$0")/.." && pwd)"
    symbolizer="${symbolizer}"
    FUZZ_ALL="${lib.concatStringsSep " " harnesses}"
    ${shellCase "fuzz_max_len" "4096" (m: m.maxLen)}
    ${shellCase "fuzz_weight" "1" (m: m.weight)}
    ${shellCase "fuzz_dict" "" (
      m: lib.optionalString (m.dict or false) "$root/share/bird-fuzz/bird.dict"
    )}
    ${builtins.readFile ./fuzz/fuzz-common.sh}
  '';

  scriptInputs = [
    pkgs.coreutils
    pkgs.findutils
    pkgs.gawk
    pkgs.gnugrep
    pkgs.gnused
  ];

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
    runtimeInputs = scriptInputs;
    # Keep going when a harness crashes; the caller reads the workdir.
    bashOptions = [ "nounset" ];
    text = scriptPrelude + ''
      # Short runs (fuzz-run, quick checks); fuzz-campaign is for long ones.
      # Env:
      #   FUZZ_TIME       seconds per harness (default 60)
      #   FUZZ_WORKDIR    output dir (default: mktemp -d)
      #   FUZZ_FORK       libFuzzer -fork jobs per harness (default 1); with
      #                   -fork, crashes are recorded and fuzzing continues
      #   FUZZ_HARNESSES  space-separated subset (default: all)
      #   FUZZ_PARALLEL   1 = run harnesses concurrently (default 1)
      time="''${FUZZ_TIME:-60}"
      workdir="''${FUZZ_WORKDIR:-$(mktemp -d)}"
      fork="''${FUZZ_FORK:-1}"
      parallel="''${FUZZ_PARALLEL:-1}"
      harnesses="''${FUZZ_HARNESSES:-$FUZZ_ALL}"

      fuzz_env 4096

      run_one() {
        local name="$1" dir="$workdir/$1"
        local extra
        fuzz_prepare "$dir" "$name"
        mapfile -t extra < <(fuzz_args "$name")
        (cd "$dir" && "$root/bin/fuzz_$name" \
          -max_total_time="$time" "''${extra[@]}" \
          -rss_limit_mb=4096 -malloc_limit_mb=4096 -timeout=25 \
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
      printf '%-10s %8s %8s %10s %7s %7s\n' harness corpus crashes execs cov unique > "$summary"
      for name in $harnesses; do
        dir="$workdir/$name"
        fuzz_repro "$dir" "$name"
        unique="$(fuzz_dedup "$dir")"
        read -r -a s <<< "$(fuzz_stats "$dir")"
        printf '%-10s %8s %8s %10s %7s %7s\n' "$name" \
          "$(find "$dir/corpus" -type f | wc -l)" "$(fuzz_crash_count "$dir")" \
          "''${s[0]}" "''${s[1]}" "$unique" >> "$summary"
      done
      cat "$summary"
      echo "$workdir"
    '';
  };

  fuzzCampaign = pkgs.writeShellApplication {
    name = "fuzz-campaign";
    runtimeInputs = scriptInputs;
    bashOptions = [ "nounset" ];
    text = scriptPrelude + builtins.readFile ./fuzz/fuzz-campaign.sh;
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
        FUZZ_SRC=${harnessSrc} FUZZ_OUT=fuzz-out FUZZERS="${fuzzerNames}" fuzz-all
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
      install -m755 ${lib.getExe fuzzCampaign} $out/bin/fuzz-campaign
      cp fuzz-out/bird.dict $out/share/bird-fuzz/
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

  # Sanitizers halt on error (known findings are suppressed, see
  # fuzz/ubsan.supp), so a seed that trips one fails the check.
  fuzz-replay = pkgs.runCommand "bird-fuzz-replay-${version}" { } ''
    export ASAN_OPTIONS="detect_leaks=0:symbolize=1"
    export ASAN_SYMBOLIZER_PATH="${symbolizer}"
    export UBSAN_SYMBOLIZER_PATH="${symbolizer}"
    export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:suppressions=${fuzzers}/share/bird-fuzz/ubsan.supp"
    for h in ${lib.concatStringsSep " " harnesses}; do
      echo "=== replay_$h ==="
      ${fuzzers}/bin/replay_$h ${fuzzers}/share/bird-fuzz/seeds/$h
    done
    touch $out
  '';

  # Source coverage: BIRD and the replay_* binaries built with clang's
  # profile instrumentation (no sanitizers, no libFuzzer), plus the
  # fuzz-coverage script that replays a corpus through them.
  covFlags = "-fprofile-instr-generate -fcoverage-mapping -fno-omit-frame-pointer -g -O1";

  birdCovBuild = birdFuzzBuild.overrideAttrs (_: {
    pname = "bird-fuzz-cov-build";
    configurePhase = ''
      runHook preConfigure
      ${ctx.configureBird [
        "CFLAGS=${covFlags}"
        "LDFLAGS=-fprofile-instr-generate"
      ]}
      runHook postConfigure
    '';
  });

  fuzzCoverageScript = pkgs.writeShellApplication {
    name = "fuzz-coverage";
    runtimeInputs = scriptInputs ++ [ pkgs.jq ];
    bashOptions = [ "nounset" ];
    text =
      scriptPrelude
      + ''
        llvm="${lib.getBin pkgs.llvm}"
        src="${src}"
      ''
      + builtins.readFile ./fuzz/fuzz-coverage.sh;
  };

  fuzz-coverage = stdenv.mkDerivation {
    pname = "bird-fuzz-coverage";
    inherit version;
    dontUnpack = true;
    dontConfigure = true;

    nativeBuildInputs = ctx.packages.nativeBuildInputs;
    inherit (ctx.packages) buildInputs;
    enableParallelBuilding = true;

    buildPhase = ''
      runHook preBuild
      cp -a ${birdCovBuild} tree
      chmod -R u+w tree
      cd tree
      make -j"$NIX_BUILD_CORES" -f Makefile -f ${harnessSrc}/fuzz.mk \
        FUZZ_SRC=${harnessSrc} FUZZ_OUT=fuzz-out FUZZERS="${fuzzerNames}" replay-all
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p $out/bin $out/share/bird-fuzz
      for h in ${lib.concatStringsSep " " harnesses}; do
        install -m755 fuzz-out/bin/replay_$h $out/bin/
      done
      install -m755 ${lib.getExe fuzzCoverageScript} $out/bin/fuzz-coverage
      ln -s ${fuzzers}/share/bird-fuzz/seeds $out/share/bird-fuzz/seeds
      runHook postInstall
    '';

    dontFixup = true;
    doCheck = false;
  };
in
{
  inherit
    birdFuzzBuild
    fuzzers
    fuzz-run
    fuzz-replay
    fuzz-coverage
    ;
}
