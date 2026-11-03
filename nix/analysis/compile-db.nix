# nix/analysis/compile-db.nix
#
# Self-contained compilation database for the static analysers.
#
# BIRD is autoconf + one hand-written Makefile, so there is no CMake export:
# we configure and run a full `bear -- make all tests` (the build also
# produces the bison/flex/m4 sources under obj/ that the .c files #include).
# The output is the configured, built source tree minus object files, with
# compile_commands.json rewritten from the sandbox path to $out so every
# 'file'/'directory'/-I resolves.
#
# The tree sits at $out root so triage's /nix/store/<hash>-<name>/ stripping
# yields repo-relative paths (proto/bgp/attrs.c).

{ ctx, src }:

let
  inherit (ctx) pkgs mkAnalysisDrv configureBird;
in
mkAnalysisDrv {
  name = "compile-db";
  inherit src;
  extraNativeBuildInputs = [
    pkgs.bear
    pkgs.jq
  ];

  buildPhase = ''
    runHook preBuild
    srcTop="$PWD"
    ${configureBird [ ]}
    bear --output "$srcTop/compile_commands.json" -- make -j"$NIX_BUILD_CORES" all tests
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    find . \( -name '*.o' -o -name '*.a' -o -name '*.d' \) -delete
    mkdir -p "$out"
    cp -r . "$out/"
    # Relocate to $out and make every "file" absolute (bear records them
    # relative to "directory"), so runners can filter on path prefixes.
    sed "s|$srcTop|$out|g" compile_commands.json \
      | jq 'map(.file = (if (.file | startswith("/")) then .file else .directory + "/" + .file end))' \
      > "$out/compile_commands.json"
    echo "compile_commands.json entries: $(jq length "$out/compile_commands.json")"
    runHook postInstall
  '';
}
