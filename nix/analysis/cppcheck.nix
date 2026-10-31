# nix/analysis/cppcheck.nix
#
# cppcheck over the compilation database (exact includes/defines per TU),
# restricted to the analysis roots. One XML run (for triage) and one text
# run (for humans) would double a slow pass, so the text report is derived
# from the XML run. Compiler builtins come from cppcheck-bird.cfg; the
# compile DB itself lives in /nix/store, so only system include dirs are
# suppressed (a blanket /nix/store/* suppression hides every finding).
{
  pkgs,
  mkCompileDbReport,
  roots,
}:

let
  runner = pkgs.writeShellApplication {
    name = "run-cppcheck-analysis";
    runtimeInputs = with pkgs; [
      cppcheck
      coreutils
      gnugrep
      jq
      python3
    ];
    text = ''
      compile_db="$1"
      output_dir="$2"

      echo "=== cppcheck Analysis (C) ==="

      # Filter the project to the analysis roots (drops tests/, tools/, generated).
      jq --arg top "$compile_db" --arg gen '${roots.generatedRegex}' '[ .[] | select(.file | test("^" + $top + "/(${builtins.concatStringsSep "|" roots.dirs})/")) | select(.file | test($gen) | not) ]' \
        "$compile_db/compile_commands.json" > "$output_dir/project.json"

      mkdir -p "$output_dir/cppcheck-build"
      cppcheck \
        --project="$output_dir/project.json" \
        --cppcheck-build-dir="$output_dir/cppcheck-build" \
        -j "$(nproc)" \
        --enable=warning,style,performance,portability \
        --inconclusive \
        --std=c11 \
        --library=posix \
        --library=gnu \
        --library=${./cppcheck-bird.cfg} \
        --suppress=missingInclude \
        --suppress=missingIncludeSystem \
        --suppress=unusedFunction \
        --suppress=unmatchedSuppression \
        --suppress='*:/nix/store/*/include/*' \
        --xml \
        2> "$output_dir/report.xml" || true
      rm -rf "$output_dir/cppcheck-build" "$output_dir/project.json"

      # Human-readable view of the same results.
      python3 - "$output_dir/report.xml" > "$output_dir/report.txt" <<'PY'
      import sys, xml.etree.ElementTree as ET
      root = ET.parse(sys.argv[1]).getroot()
      for e in root.iter("error"):
          loc = e.find("location")
          where = f'{loc.get("file")}:{loc.get("line")}' if loc is not None else "?"
          print(f'{where}: {e.get("severity")}: {e.get("msg")} [{e.get("id")}]')
      PY

      grep -c ': \(error\|warning\|style\|performance\|portability\):' "$output_dir/report.txt" > "$output_dir/count.txt" || echo 0 > "$output_dir/count.txt"
    '';
  };
in
mkCompileDbReport "cppcheck" runner
