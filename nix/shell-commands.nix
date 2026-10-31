# nix/shell-commands.nix
#
# Dev-shell helper commands, written as writeShellApplication packages
# (shellcheck'd at build time) rather than shellHook functions. They are put
# on PATH by nix/devshell.nix and also exposed as flake packages.
#
#   bird-configure   autoreconf + ./configure with the flake's flag set
#   bird-build       make -j$(nproc) (configures first if needed)
#   bird-check       make check (unit tests)
#   bird-compdb      bear -- make, for clangd / clang-tidy
#   bird-help        list commands and flake targets

{ ctx }:

let
  inherit (ctx) pkgs lib;

  configureLine = lib.escapeShellArgs ctx.configureFlags;

  bird-configure = pkgs.writeShellApplication {
    name = "bird-configure";
    text = ''
      top=$(git rev-parse --show-toplevel)
      cd "$top"
      autoreconf -fi
      ./configure --prefix=/usr ${configureLine} "$@"
    '';
  };

  bird-build = pkgs.writeShellApplication {
    name = "bird-build";
    runtimeInputs = [ bird-configure ];
    text = ''
      top=$(git rev-parse --show-toplevel)
      cd "$top"
      [ -f Makefile ] || bird-configure
      make -j"$(nproc)" "$@"
    '';
  };

  bird-check = pkgs.writeShellApplication {
    name = "bird-check";
    runtimeInputs = [ bird-build ];
    text = ''
      top=$(git rev-parse --show-toplevel)
      cd "$top"
      bird-build
      make -j"$(nproc)" check "$@"
    '';
  };

  bird-compdb = pkgs.writeShellApplication {
    name = "bird-compdb";
    runtimeInputs = [
      bird-configure
      pkgs.bear
    ];
    text = ''
      top=$(git rev-parse --show-toplevel)
      cd "$top"
      [ -f Makefile ] || bird-configure
      bear -- make -j"$(nproc)" all tests "$@"
    '';
  };

  bird-help = pkgs.writeShellApplication {
    name = "bird-help";
    text = ''
      cat <<'HELP'
      BIRD dev shell (flake version ${ctx.version})

      Shell commands:
        bird-configure [args]  autoreconf + configure (flake flag set, extra args appended)
        bird-build [targets]   make -j$(nproc)
        bird-check             make check (unit tests)
        bird-compdb            bear -- make  -> compile_commands.json

      Flake targets:
        nix build .#bird                      bird, birdc, birdcl (runs make check)
        nix build .#analysis-quick            clang-tidy + cppcheck
        nix build .#analysis-standard         + flawfinder, scan-build, gcc warnings
        nix build .#analysis-deep             + gcc -fanalyzer, semgrep
        nix build .#analysis-<tool>           one tool (see nix/README.md)
        nix build .#analysis-sanitizers       ASan+UBSan make check
        nix build .#analysis-tsan             TSan make check
        nix build .#analysis-valgrind         unit tests under valgrind
        nix build .#fuzz                      libFuzzer harnesses; ./result/bin/run-fuzzers
        nix build .#fuzz-run                  bounded fuzz run in the sandbox
        nix flake check                       nix lint + build + fuzz replay
      HELP
    '';
  };
in
{
  packages = {
    inherit
      bird-configure
      bird-build
      bird-check
      bird-compdb
      bird-help
      ;
  };
  all = [
    bird-configure
    bird-build
    bird-check
    bird-compdb
    bird-help
  ];
}
