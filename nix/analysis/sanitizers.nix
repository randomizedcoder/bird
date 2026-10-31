# nix/analysis/sanitizers.nix
#
# Dynamic analysis: build BIRD with its own sanitizer switches
# (configure.ac --enable-asan/--enable-ubsan/--enable-tsan) and run the
# unit-test suite (`make check`: every */*_test.c, linked against all
# daemon objects) as the exercise.
#
#   sanitizers         ASan + LSan + UBSan
#   thread-sanitizer   TSan (clang)
#
# Makefile.in runs each test with stderr sent to /dev/null and marks a pass
# with <test>.ok, so every sanitizer report goes to a per-process log
# (log_path) and the pass/fail list comes from the .ok stamps. Findings
# never fail the build; only a check run that didn't happen at all does.
{ ctx, src }:

let
  inherit (ctx)
    pkgs
    mkAnalysisDrv
    configureBird
    scrubStore
    ;

  mkSanBuild =
    {
      name,
      configureArgs,
      runtimeEnv,
      markerGrep,
      description,
      useClang ? false,
    }:
    mkAnalysisDrv {
      inherit name src;
      extraNativeBuildInputs = ctx.packages.checkInputs ++ [ pkgs.llvm ];
      stdenv = if useClang then pkgs.clangStdenv else pkgs.stdenv;
      hardeningDisable = [ "fortify" ];

      buildPhase = ''
        runHook preBuild
        ${configureBird configureArgs}
        make -j"$NIX_BUILD_CORES" all tests
        runHook postBuild
      '';

      installPhase = ''
        runHook preInstall
        mkdir -p $out "$TMPDIR/san"
        export ASAN_SYMBOLIZER_PATH=${pkgs.llvm}/bin/llvm-symbolizer
        ${runtimeEnv}

        make -k -j"$NIX_BUILD_CORES" check > "$TMPDIR/check.log" 2>&1 \
          && echo "check: passed" > $out/check.txt \
          || echo "check: failed (exit $?)" > $out/check.txt
        cp "$TMPDIR/check.log" $out/check.log

        # Test programs are the executables next to their *_test.o.
        find obj -name '*_test.o' | sed 's/\.o$//' | sort > "$TMPDIR/tests.txt"
        : > $out/failed-tests.txt
        while read -r t; do
          [ -f "$t.ok" ] || echo "''${t#obj/}" >> $out/failed-tests.txt
        done < "$TMPDIR/tests.txt"
        total=$(wc -l < "$TMPDIR/tests.txt")
        failed=$(wc -l < $out/failed-tests.txt)

        # Sanitizer logs: one file per process.
        cat "$TMPDIR"/san/* 2>/dev/null | ${scrubStore} | sed "s|$PWD/||g" > $out/report.txt || true
        # Also catch anything make itself printed.
        grep -E "${markerGrep}" $out/check.log >> $out/report.txt || true
        violations=$(grep -cE "${markerGrep}" $out/report.txt || true)
        echo "''${violations:-0}" > $out/count.txt

        # Unique first-frame summary lines, for the report.
        grep -E '^SUMMARY: ' $out/report.txt | sort | uniq -c | sort -rn > $out/unique.txt || true

        {
          echo "=== ${description} (make check) ==="
          cat $out/check.txt
          echo "unit tests: $((total - failed)) passed, $failed failed (of $total)"
          if [ "$failed" -gt 0 ]; then sed 's/^/  failed: /' $out/failed-tests.txt; fi
          echo "sanitizer report lines: $(cat $out/count.txt)"
          echo ""
          cat $out/unique.txt
        } > $out/summary.txt
        cat $out/summary.txt

        if [ "$total" -eq 0 ]; then
          echo "${name}: no unit tests were built" >&2
          exit 1
        fi
        runHook postInstall
      '';
    };
in
{
  sanitizers = mkSanBuild {
    name = "sanitizers";
    description = "ASan + LSan + UBSan";
    configureArgs = [
      "--enable-asan"
      "--enable-ubsan"
    ];
    runtimeEnv = ''
      export ASAN_OPTIONS="detect_leaks=1:halt_on_error=0:abort_on_error=0:log_path=$TMPDIR/san/asan:symbolize=1"
      export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=$TMPDIR/san/ubsan"
      export LSAN_OPTIONS="log_path=$TMPDIR/san/lsan"
    '';
    markerGrep = "ERROR: (Address|Leak)Sanitizer|runtime error:|SUMMARY: (Address|Undefined|Leak)Sanitizer";
  };

  thread-sanitizer = mkSanBuild {
    name = "thread-sanitizer";
    description = "ThreadSanitizer";
    useClang = true;
    configureArgs = [ "--enable-tsan" ];
    runtimeEnv = ''
      export TSAN_OPTIONS="halt_on_error=0:exitcode=0:log_path=$TMPDIR/san/tsan:second_deadlock_stack=1"
    '';
    markerGrep = "WARNING: ThreadSanitizer|SUMMARY: ThreadSanitizer";
  };
}
