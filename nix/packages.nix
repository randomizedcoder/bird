# nix/packages.nix
#
# Dependency and tool sets for the BIRD flake. The build/runtime lists mirror
# nixpkgs' own bird derivation (pkgs/by-name/bi/bird2): flex/bison/m4 for
# the config grammar, readline + ncurses for birdc, libssh for RPKI over SSH.
#
# Fields:
#   nativeBuildInputs   tools needed to bootstrap + build
#   buildInputs         libraries BIRD links against
#   checkInputs         extra tools for `make check` (none: tests are C)
#   analysisTools       static/dynamic analysers used by nix/analysis
#   devTools            interactive extras for the dev shell
#   allPackages         everything, for the dev shell

{ pkgs }:

rec {
  nativeBuildInputs = with pkgs; [
    autoconf
    automake
    bison
    flex
    gnum4
    python3
  ];

  buildInputs = with pkgs; [
    libssh
    ncurses
    readline
  ];

  checkInputs = [ ];

  analysisTools = with pkgs; [
    clang
    clang-tools
    clang-analyzer
    cppcheck
    flawfinder
    semgrep
    bear
    valgrind
  ];

  devTools = with pkgs; [
    gdb
    strace
    ltrace
    shellcheck
    jq
    git
    nixfmt
    deadnix
    statix
  ];

  allPackages = nativeBuildInputs ++ buildInputs ++ checkInputs ++ analysisTools ++ devTools;
}
