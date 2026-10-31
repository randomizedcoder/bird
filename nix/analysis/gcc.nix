# nix/analysis/gcc.nix
#
# GCC-based analysis as two full autoconf builds:
#   gcc-warnings  bug-oriented extra -W… flags, capture the diagnostics
#   gcc-analyzer  -fanalyzer path-sensitive (interprocedural) analysis
#
# Flags go in through CFLAGS on the configure line; BIRD then appends its
# own warning set (configure.ac: -Wall -Wextra -Wstrict-prototypes ...).
# `make -k` so one TU's problem doesn't hide the rest. Very noisy flags
# (-Wconversion, -Wsign-conversion, -Wpedantic) are left out on purpose.
{ ctx, src }:

let
  inherit (ctx)
    lib
    mkAnalysisDrv
    configureBird
    ;
  roots = import ./roots.nix;

  gccWarningFlags = [
    "-Wall"
    "-Wextra"
    "-Wformat=2"
    "-Wformat-overflow=2"
    "-Wformat-truncation=2"
    "-Wformat-signedness"
    "-Wstringop-overflow=4"
    "-Warray-bounds=2"
    "-Wshadow=local"
    "-Wduplicated-cond"
    "-Wduplicated-branches"
    "-Wlogical-op"
    "-Wnull-dereference"
    "-Wimplicit-fallthrough"
    "-Walloca"
    "-Wvla"
    "-Wcast-align=strict"
    "-Wuse-after-free=3"
    "-Wno-missing-field-initializers"
    "-Wno-unused-parameter"
    "-Wno-sign-compare"
  ];

  mkGccAnalysisBuild =
    name: extraFlags:
    mkAnalysisDrv {
      inherit name src;

      buildPhase = ''
        runHook preBuild
        srcTop="$PWD"
        ${configureBird [ "CFLAGS=-g -O2 ${lib.concatStringsSep " " extraFlags}" ]}
        make -k -j"$NIX_BUILD_CORES" all tests 2>&1 \
          | tee "$NIX_BUILD_TOP/build-output.log" || true
        runHook postBuild
      '';

      installPhase = ''
        mkdir -p $out
        # Repo-relative, in-root diagnostics only; dedupe (headers are
        # reported once per including TU). Full log kept alongside.
        grep -E ': warning:|: error:' "$NIX_BUILD_TOP/build-output.log" \
          | sed "s|$srcTop/||g" \
          | grep -E '^(${builtins.concatStringsSep "|" roots.dirs})/' \
          | sort -u > $out/report.txt || true
        findings=$(wc -l < $out/report.txt)
        echo "$findings" > $out/count.txt
        cp "$NIX_BUILD_TOP/build-output.log" $out/full-build.log
        {
          echo "=== ${name} Analysis ==="
          echo "Extra flags: ${lib.concatStringsSep " " extraFlags}"
          echo "Findings: $findings unique warnings/errors"
        } > $out/summary.txt
      '';
    };
in
{
  gcc-warnings = mkGccAnalysisBuild "gcc-warnings" gccWarningFlags;
  gcc-analyzer = mkGccAnalysisBuild "gcc-analyzer" [
    "-fanalyzer"
    "-fdiagnostics-plain-output"
    "-fanalyzer-verbosity=1"
  ];
}
