# nix/lib.nix
#
# Shared build context for the BIRD flake. Built once in flake.nix and
# threaded (as `ctx`) into the build, dev shell, and analysis modules.
#
# Fields:
#   pkgs, lib          the flake's per-system inputs, passed through
#   packages           dependency / tool sets (nix/packages.nix)
#   version            the VERSION file
#   configureFlags     the shared ./configure flag list
#   configureBird      shell snippet: autoreconf + configure with extra flags
#   scrubStore         sed program stripping /nix/store/<hash>-<name>/
#   mkAnalysisDrv      base derivation for the analysis builds
#
# Usage:
#   ctx = import ./nix/lib.nix { inherit pkgs lib; src = ./.; };

{
  pkgs,
  lib,
  src,
}:

let
  packages = import ./packages.nix { inherit pkgs; };

  version = lib.removeSuffix "\n" (builtins.readFile (src + "/VERSION"));

  # Feature set used by every build: all protocols (the default), pthreads
  # (needed for BFD), libssh for RPKI-over-SSH, plus the nixpkgs path flags.
  # --enable-debug is left off: it adds -O0 and dmalloc/efence probing,
  # and the analysis builds set their own CFLAGS.
  configureFlags = [
    "--enable-pthreads"
    "--enable-libssh"
    "--localstatedir=/var"
    "--runstatedir=/run/bird"
    "--sysconfdir=/etc"
  ];

  # autoreconf + configure in the current directory, for the analysis and
  # fuzz builds. `extra` is a list of additional configure arguments (e.g.
  # sanitizer switches, CC=clang). LTO is forced off (the probe's cache
  # variable): with -flto, -fanalyzer and the sanitizer/fuzzer
  # instrumentation run at link time, and per-TU diagnostics get lost.
  configureBird = extra: ''
    patchShebangs .
    autoreconf -fi
    ./configure --prefix=/usr ${lib.escapeShellArgs (configureFlags ++ [ "bird_cv_c_lto=no" ] ++ extra)}
  '';

  scrubStore = ''sed 's|/nix/store/[a-z0-9]\{32\}-[^/]*/||g' '';

  # Base derivation for the analysis builds: shared inputs, no install,
  # no fixup. Callers supply buildPhase / installPhase.
  mkAnalysisDrv =
    {
      name,
      extraNativeBuildInputs ? [ ],
      ...
    }@args:
    pkgs.stdenv.mkDerivation (
      {
        pname = "bird-analysis-${name}";
        inherit version src;
        nativeBuildInputs = packages.nativeBuildInputs ++ extraNativeBuildInputs;
        inherit (packages) buildInputs;
        dontConfigure = true;
        dontFixup = true;
        doCheck = false;
        enableParallelBuilding = true;
      }
      // (removeAttrs args [
        "name"
        "extraNativeBuildInputs"
      ])
    );
in
{
  inherit
    pkgs
    lib
    packages
    version
    configureFlags
    configureBird
    scrubStore
    mkAnalysisDrv
    ;
}
