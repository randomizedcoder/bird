# nix/devshell.nix
#
# `nix develop`: every build dependency, the analysis tools, and the
# bird-* helper commands (nix/shell-commands.nix) on PATH.

{ ctx, shellCommands }:

ctx.pkgs.mkShell {
  packages = ctx.packages.allPackages ++ shellCommands.all;

  # pkgs.clang's setup hook would otherwise make clang the default CC;
  # BIRD's primary toolchain is gcc. Use CC=clang bird-configure to switch.
  shellHook = ''
    export CC=gcc CXX=g++
    export PS1="\[\e[1;32m\][bird-nix]\[\e[0m\] \w \$ "
    bird-help
  '';
}
