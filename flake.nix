#
# flake.nix for BIRD
#
# A reproducible development environment, a hermetic build, and a suite of
# static, dynamic, and fuzz analysis targets. This slim flake wires together
# single-purpose modules under nix/ (see nix/README.md).
#
# Enter the development shell:
#   nix develop                       # then: bird-help
#
# Build the daemon (unit tests run as part of the build):
#   nix build .#bird && ./result/sbin/bird --version
#
# Run the analysis (nix/README.md lists every target):
#   nix build .#analysis-deep && cat result/summary.txt
#   nix build .#fuzz && FUZZ_TIME=300 ./result/bin/run-fuzzers
#
# NOTE: flakes only see git-tracked files. After adding or editing files
# under nix/, `git add` them before `nix build` / `nix develop`.
#
{
  description = "BIRD Internet Routing Daemon — build, dev shell, static analysis and fuzzing";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # semgrep from nixos-unstable currently fails to build (patchelf on
    # semgrep-core); take it from the stable channel until that is fixed.
    nixpkgs-semgrep.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  # Linux-only: the netlink sysdep, libFuzzer and the sanitizer / valgrind
  # tooling are what this flake is for, so don't generate Darwin attrs.
  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      nixpkgs-semgrep,
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            (_final: _prev: { inherit (nixpkgs-semgrep.legacyPackages.${system}) semgrep; })
          ];
        };
        inherit (nixpkgs) lib;
        # The BIRD tree without the Nix files, so editing nix/ doesn't
        # invalidate every BIRD build. Modules reference their own helper
        # files (harnesses, rules, triage) as Nix paths instead.
        src = lib.cleanSourceWith {
          src = self;
          filter =
            path: fileType:
            let
              rel = lib.removePrefix (toString self + "/") (toString path);
            in
            lib.cleanSourceFilter path fileType
            && !(rel == "nix" || lib.hasPrefix "nix/" rel || rel == "flake.nix" || rel == "flake.lock");
        };

        ctx = import ./nix/lib.nix { inherit pkgs lib src; };

        bird = import ./nix/derivation.nix { inherit ctx src; };

        shellCommands = import ./nix/shell-commands.nix { inherit ctx; };
        devshell = import ./nix/devshell.nix { inherit ctx shellCommands; };

        analysis = import ./nix/analysis { inherit ctx src; };

        checks = import ./nix/checks {
          inherit pkgs;
          src = self;
        };
      in
      {
        packages = {
          inherit bird;
          default = bird;

          # Compilation database (consumed by clang-tidy / cppcheck).
          compile-db = analysis.compileDb;

          # Aggregate analysis levels.
          analysis-quick = analysis.quick;
          analysis-standard = analysis.standard;
          analysis-deep = analysis.deep;

          # Per-tool static analysis.
          analysis-clang-tidy = analysis.clang-tidy;
          analysis-cppcheck = analysis.cppcheck;
          analysis-flawfinder = analysis.flawfinder;
          analysis-semgrep = analysis.semgrep;
          analysis-clang-analyzer = analysis.clang-analyzer;
          analysis-gcc-warnings = analysis.gcc-warnings;
          analysis-gcc-analyzer = analysis.gcc-analyzer;

          # Dynamic analysis: sanitizer builds running `make check`.
          analysis-sanitizers = analysis.sanitizers;
          analysis-tsan = analysis.thread-sanitizer;
          analysis-valgrind = analysis.valgrind;

          # Fuzzing.
          fuzz = analysis.fuzzers; # harnesses + corpora + run-fuzzers + fuzz-campaign
          inherit (analysis) fuzz-run; # bounded sandboxed run, collect crashes
          inherit (analysis) fuzz-coverage; # llvm-cov build + fuzz-coverage report
        }
        // shellCommands.packages;

        checks = checks // {
          inherit bird;
          inherit (analysis) fuzz-replay triage-tests;
        };

        # nix run .#fuzz-campaign -- --hours 12   (long, resumable fuzzing)
        # nix run .#fuzz-coverage -- ~/bird-fuzz  (what the corpus reaches)
        apps = {
          fuzz-campaign = {
            type = "app";
            program = "${analysis.fuzzers}/bin/fuzz-campaign";
          };
          fuzz-coverage = {
            type = "app";
            program = "${analysis.fuzz-coverage}/bin/fuzz-coverage";
          };
        };

        devShells.default = devshell;

        formatter = pkgs.nixfmt-tree;
      }
    );
}
