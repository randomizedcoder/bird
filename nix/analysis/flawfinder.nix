# nix/analysis/flawfinder.nix
#
# flawfinder: pattern-matches risky C library calls in raw source. No
# compile DB needed; scans the analysis roots (roots.nix).
{
  pkgs,
  mkSourceReport,
  roots,
}:

let
  runner = pkgs.writeShellApplication {
    name = "run-flawfinder-analysis";
    runtimeInputs = with pkgs; [
      flawfinder
      coreutils
      gnugrep
    ];
    text = ''
      source_dir="$1"
      output_dir="$2"

      echo "=== flawfinder Analysis ==="

      dirs=()
      for d in ${builtins.concatStringsSep " " roots.dirs}; do
        dirs+=("$source_dir/$d")
      done

      flawfinder \
        --minlevel=1 \
        --columns \
        --context \
        --singleline \
        "''${dirs[@]}" \
        > "$output_dir/report.txt" 2>&1 || true

      # flawfinder prints a summary line "Hits = N"
      findings=$(grep -oP 'Hits = \K[0-9]+' "$output_dir/report.txt" || true)
      echo "''${findings:-0}" > "$output_dir/count.txt"
    '';
  };
in
mkSourceReport "flawfinder" runner
