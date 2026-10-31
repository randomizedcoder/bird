# nix/analysis/clang-tidy.nix
#
# clang-tidy over the compilation database, every non-generated .c under the
# analysis roots (roots.nix). Check set favours bug classes over style:
# bugprone-*, cert-*, clang-analyzer-*, misc-*, plus a few readability ones
# triage scores as noise. BIRD has no .clang-tidy; --config pins the
# behaviour regardless.
{
  pkgs,
  mkCompileDbReport,
  roots,
}:

let
  runner = pkgs.writeShellApplication {
    name = "run-clang-tidy-analysis";
    runtimeInputs = with pkgs; [
      clang-tools
      coreutils
      findutils
      gnugrep
      jq
    ];
    text = ''
      compile_db="$1"
      output_dir="$2"

      echo "=== clang-tidy Analysis (C) ==="

      # Only files that are actually in the compile DB (configured daemons).
      jq -r '.[].file' "$compile_db/compile_commands.json" \
        | grep -E '^'"$compile_db"'/(${builtins.concatStringsSep "|" roots.dirs})/[^ ]*\.c$' \
        | grep -Ev '${roots.generatedRegex}' \
        | sort -u > "$output_dir/files.txt"
      echo "files: $(wc -l < "$output_dir/files.txt")"

      tr '\n' '\0' < "$output_dir/files.txt" | \
        xargs -0 -P "$(nproc)" -n 4 \
          clang-tidy \
            -p "$compile_db" \
            --quiet \
            --config='WarningsAsErrors: ""' \
            --header-filter='.*/(${builtins.concatStringsSep "|" roots.dirs})/.*' \
            --checks='-*,bugprone-*,cert-*,clang-analyzer-*,misc-*,-misc-include-cleaner,-misc-no-recursion,-bugprone-easily-swappable-parameters,-bugprone-reserved-identifier,-cert-dcl37-c,-cert-dcl51-cpp,-bugprone-macro-parentheses' \
        > "$output_dir/report.txt" 2>&1 || true

      findings=$(grep -c ': warning:\|: error:' "$output_dir/report.txt" || true)
      echo "''${findings:-0}" > "$output_dir/count.txt"
    '';
  };
in
mkCompileDbReport "clang-tidy" runner
