# nix/analysis/clang-analyzer.nix
#
# Clang Static Analyzer (scan-build) over the full autoconf build.
# scan-build wraps both ./configure and make so the analyzer wrapper is
# baked in as $CC and every translation unit (daemon, client, tests) is
# analysed. Default checkers, the set BIRD's own `make static-scan` enables
# (Makefile.in STATIC_CHECKERS_*), plus a few security / taint ones that
# suit a packet-parsing codebase.
{ ctx, src }:

let
  inherit (ctx)
    pkgs
    lib
    mkAnalysisDrv
    configureBird
    ;

  scanBuildCheckers = lib.concatMapStringsSep " " (c: "-enable-checker ${c}") [
    "core.NullDereference"
    "core.DivideZero"
    "core.UndefinedBinaryOperatorResult"
    "core.uninitialized.Assign"
    "security.insecureAPI.getpw"
    "security.insecureAPI.gets"
    "security.insecureAPI.vfork"
    "security.ArrayBound"
    "unix.Malloc"
    "unix.MallocSizeof"
    "unix.MismatchedDeallocator"
    "optin.taint.TaintedAlloc"
    # Makefile.in STATIC_CHECKERS_ENABLE
    "nullability.NullableDereferenced"
    "nullability.NullablePassedToNonnull"
    "nullability.NullableReturnedFromNonnull"
    "optin.portability.UnixAPI"
    "valist.CopyToSelf"
    "valist.Uninitialized"
    "valist.Unterminated"
  ];

  # Configure + build in one script so both run under scan-build's
  # compiler interception. $1 = source root. patchShebangs is a stdenv
  # shell function, so buildPhase runs it before entering this script.
  analyzeScript = pkgs.writeShellApplication {
    name = "analyze-build";
    text = ''
      cd "$1"
      ${lib.replaceStrings [ "patchShebangs .\n" ] [ "" ] (configureBird [ ])}
      make -k -j"$NIX_BUILD_CORES" all tests
    '';
  };
in
mkAnalysisDrv {
  name = "clang-analyzer";
  inherit src;

  extraNativeBuildInputs = [
    pkgs.clang
    pkgs.clang-analyzer
  ];

  # Keep the cc-wrapper's -D_FORTIFY_SOURCE out of the analyzer's view;
  # it rewrites the libc calls the unix.* checkers model.
  hardeningDisable = [
    "fortify"
    "fortify3"
  ];

  buildPhase = ''
    runHook preBuild
    srcTop="$PWD"
    patchShebangs .
    # clang-analyzer's scan-build: the copy in pkgs.clang has a
    # /usr/bin/env shebang that fails in the sandbox.
    ${pkgs.clang-analyzer}/bin/scan-build \
      --use-analyzer=${pkgs.clang}/bin/clang \
      ${scanBuildCheckers} \
      -disable-checker deadcode.DeadStores \
      -o "$NIX_BUILD_TOP/scan-results" \
      ${lib.getExe analyzeScript} "$srcTop" \
      2>&1 | tee "$NIX_BUILD_TOP/scan-build.log" || true
    runHook postBuild
  '';

  installPhase = ''
    mkdir -p $out
    if [ -d "$NIX_BUILD_TOP/scan-results" ] && \
       [ "$(ls -A "$NIX_BUILD_TOP/scan-results" 2>/dev/null)" ]; then
      mkdir -p $out/html-report
      cp -r "$NIX_BUILD_TOP/scan-results"/* $out/html-report/ 2>/dev/null || true
    fi

    # scan-build prints "scan-build: N bugs found."
    findings=$(grep -oP '\d+ bugs? found' "$NIX_BUILD_TOP/scan-build.log" \
      | grep -oP '^\d+' | head -1 || true)
    echo "''${findings:-0}" > $out/count.txt

    # Repo-relative analyzer diagnostics for triage (the build's ordinary
    # compiler warnings carry no [checker] tag, analyzer ones do).
    grep -E ': warning:.*\[(core|unix|security|alpha|optin|deadcode|cplusplus|nullability|valist)\.' \
      "$NIX_BUILD_TOP/scan-build.log" \
      | sed "s|$srcTop/||g" | sort -u > $out/report.txt || true
    cp "$NIX_BUILD_TOP/scan-build.log" $out/full-build.log

    {
      echo "=== Clang Static Analyzer ==="
      echo "Findings: $(cat $out/count.txt) (html-report/ has path traces)"
    } > $out/summary.txt
  '';
}
