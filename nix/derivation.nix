# nix/derivation.nix
#
# Hermetic BIRD build from the working tree.
#
# Arguments:
#   ctx                  shared context (nix/lib.nix)
#   src                  source tree (the flake root)
#   sanitizers           subset of [ "asan" "ubsan" "tsan" ]; each maps to
#                        BIRD's own --enable-<x> switch (configure.ac)
#   stdenv               override to build with clang (pkgs.clangStdenv)
#   doCheck              run `make check` (the */*_test.c unit tests)
#   extraConfigureFlags  appended to the shared flag list
#
# Usage:
#   nix build .#bird && ./result/sbin/bird --version

{
  ctx,
  src,
  sanitizers ? [ ],
  stdenv ? ctx.pkgs.stdenv,
  doCheck ? true,
  extraConfigureFlags ? [ ],
  pnameSuffix ? "",
}:

let
  inherit (ctx) lib packages;
in
stdenv.mkDerivation {
  pname = "bird${pnameSuffix}";
  inherit (ctx) version;
  inherit src doCheck;

  inherit (packages) nativeBuildInputs buildInputs;
  nativeCheckInputs = packages.checkInputs;

  configureFlags = ctx.configureFlags ++ map (s: "--enable-${s}") sanitizers ++ extraConfigureFlags;

  preConfigure = ''
    patchShebangs .
    autoreconf -fi
  '';

  # Install under $out instead of the /etc and /var compiled-in paths.
  installFlags = [
    "sysconfdir=${placeholder "out"}/etc"
    "localstatedir=${placeholder "out"}/var"
    "runstatedir=${placeholder "out"}/run/bird"
  ];

  enableParallelBuilding = true;
  hardeningDisable = lib.optionals (sanitizers != [ ]) [ "fortify" ];

  meta = {
    description = "BIRD Internet Routing Daemon (built from this tree)";
    homepage = "https://bird.nic.cz/";
    license = lib.licenses.gpl2Plus;
    platforms = lib.platforms.linux;
    mainProgram = "bird";
  };
}
