# nix/analysis/default.nix
#
# Analysis entry point for BIRD, following the rocm-ernic / xdp2 framework.
#
# Static tools (scoped to the daemon + lib roots in roots.nix):
#   clang-tidy, cppcheck           via the compilation database
#   flawfinder, semgrep            raw-source scanners (semgrep: BIRD rules)
#   gcc-warnings, gcc-analyzer     full builds with extra diagnostics
#   clang-analyzer                 scan-build path-sensitive analysis
#
# Aggregate levels (each also runs the triage prioritiser):
#   quick     = clang-tidy + cppcheck
#   standard  = quick + flawfinder + clang-analyzer + gcc-warnings
#   deep      = standard + gcc-analyzer + semgrep
#
# Dynamic: sanitizers (ASan+UBSan), thread-sanitizer, valgrind — `make check`
# under instrumentation. Fuzzing: fuzz.nix.
#
# Usage:
#   nix build .#analysis-quick | .#analysis-standard | .#analysis-deep
#   nix build .#analysis-cppcheck   (etc. per-tool)

{ ctx, src }:

let
  inherit (ctx) pkgs lib;
  python = pkgs.python3;
  roots = import ./roots.nix;

  # ── Compilation database ────────────────────────────────────────
  compileDb = import ./compile-db.nix { inherit ctx src; };

  # ── Helpers ─────────────────────────────────────────────────────
  # Tools that consume the compilation DB: script args = (compileDb, out).
  mkCompileDbReport =
    name: script:
    pkgs.runCommand "bird-analysis-${name}" { nativeBuildInputs = [ script ]; } ''
      mkdir -p $out
      ${lib.getExe script} ${compileDb} $out
    '';

  # Tools that scan raw source: script args = (src, out).
  mkSourceReport =
    name: script:
    pkgs.runCommand "bird-analysis-${name}" { nativeBuildInputs = [ script ]; } ''
      mkdir -p $out
      ${lib.getExe script} ${src} $out
    '';

  # ── Individual tool targets ─────────────────────────────────────
  clang-tidy = import ./clang-tidy.nix { inherit pkgs mkCompileDbReport roots; };
  cppcheck = import ./cppcheck.nix { inherit pkgs mkCompileDbReport roots; };
  flawfinder = import ./flawfinder.nix { inherit pkgs mkSourceReport roots; };
  semgrep = import ./semgrep.nix { inherit pkgs mkSourceReport roots; };
  gccTargets = import ./gcc.nix { inherit ctx src; };
  clang-analyzer = import ./clang-analyzer.nix { inherit ctx src; };

  # ── Dynamic analysis (not part of the static triage aggregates) ─
  sanitizerTargets = import ./sanitizers.nix { inherit ctx src; };
  valgrind = import ./valgrind.nix { inherit ctx src; };

  # ── Fuzzing ─────────────────────────────────────────────────────
  fuzzTargets = import ./fuzz.nix { inherit ctx src; };

  # ── Triage ──────────────────────────────────────────────────────
  triagePath = ./triage;

  triage-tests = pkgs.runCommand "bird-analysis-triage-tests" { nativeBuildInputs = [ python ]; } ''
    export PYTHONDONTWRITEBYTECODE=1
    python3 ${triagePath}/test_triage.py -v 2>&1 | tee $out
  '';

  # Build an aggregate: symlink each tool's output under $out/<name>, run
  # the triage prioritiser, and print a summary table.
  mkAggregate =
    level: tools: summaryExtra:
    pkgs.runCommand "bird-analysis-${level}" { nativeBuildInputs = [ python ]; } ''
      mkdir -p $out
      ${lib.concatMapStringsSep "\n" (t: "ln -s ${t.drv} $out/${t.name}") tools}

      python3 ${triagePath} $out --output-dir $out/triage

      {
        echo "=== Analysis Summary (${level}) ==="
        echo ""
        ${lib.concatMapStringsSep "\n" (t: ''
          echo "${lib.fixedWidthString 16 " " (t.name + ":")} $(cat ${t.drv}/count.txt) findings"
          if [ -f ${t.drv}/coverage.txt ]; then cat ${t.drv}/coverage.txt; fi
        '') tools}
        echo "${
          lib.fixedWidthString 16 " " "triage:"
        } $(cat $out/triage/count.txt 2>/dev/null || echo 0) high-confidence findings"
        echo ""
        ${summaryExtra}
      } > $out/summary.txt
      cat $out/summary.txt
    '';

  quickTools = [
    {
      name = "clang-tidy";
      drv = clang-tidy;
    }
    {
      name = "cppcheck";
      drv = cppcheck;
    }
  ];

  standardTools = quickTools ++ [
    {
      name = "flawfinder";
      drv = flawfinder;
    }
    {
      name = "clang-analyzer";
      drv = clang-analyzer;
    }
    {
      name = "gcc-warnings";
      drv = gccTargets.gcc-warnings;
    }
  ];

  deepTools = standardTools ++ [
    {
      name = "gcc-analyzer";
      drv = gccTargets.gcc-analyzer;
    }
    {
      name = "semgrep";
      drv = semgrep;
    }
  ];

  quick =
    mkAggregate "quick" quickTools
      ''echo "Run 'nix build .#analysis-standard' for a broader sweep."'';
  standard =
    mkAggregate "standard" standardTools
      ''echo "Run 'nix build .#analysis-deep' for gcc -fanalyzer + semgrep."'';
  deep = mkAggregate "deep" deepTools ''echo "All static analysis tools completed."'';
in
{
  inherit
    compileDb
    clang-tidy
    cppcheck
    flawfinder
    semgrep
    clang-analyzer
    quick
    standard
    deep
    valgrind
    triage-tests
    ;
  inherit (gccTargets) gcc-warnings gcc-analyzer;
  inherit (sanitizerTargets) sanitizers thread-sanitizer;
  inherit (fuzzTargets) fuzzers fuzz-run fuzz-replay;
}
