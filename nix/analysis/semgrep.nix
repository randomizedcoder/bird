# nix/analysis/semgrep.nix
#
# semgrep with BIRD's C ruleset (semgrep-rules.yaml) over the analysis roots.
# Runs fully offline.
#
# Before scanning, each fixture in semgrep-tests/ is run with
# `semgrep --test` (`ruleid:` lines must match, `ok:` lines must not); a
# failing fixture or a rule that fails to parse fails the build, since
# semgrep would otherwise skip the rule with only a JSON "errors" entry.
# semgrep-report.jq validates the JSON and prints the finding count. A rule
# timeout fails it (that file went unscanned), so --timeout is generous: the
# 5 s default trips on proto/bgp/packets.c on a loaded machine.
{
  pkgs,
  mkSourceReport,
  roots,
}:

let
  rulesFile = ./semgrep-rules.yaml;
  testsDir = ./semgrep-tests;

  runner = pkgs.writeShellApplication {
    name = "run-semgrep-analysis";
    runtimeInputs = with pkgs; [
      semgrep
      coreutils
      gnugrep
      cacert
      jq
    ];
    text = ''
      source_dir="$1"
      output_dir="$2"

      echo "=== semgrep Analysis ==="

      export SEMGREP_ENABLE_VERSION_CHECK=0
      export SEMGREP_SEND_METRICS=off
      export SSL_CERT_FILE="${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
      export OTEL_TRACES_EXPORTER=none
      semgrep_home="$(mktemp -d)"
      trap 'rm -rf "$semgrep_home"' EXIT
      export HOME="$semgrep_home"
      export SEMGREP_SETTINGS_FILE="$semgrep_home/settings.yml"
      export SEMGREP_LOG_FILE="$semgrep_home/semgrep.log"

      for fixture in ${testsDir}/*.c; do
        t="$output_dir/rule-test-$(basename "$fixture" .c).txt"
        echo "semgrep --test $(basename "$fixture")"
        semgrep --test --config ${rulesFile} "$fixture" > "$t" 2>&1 || {
          cat "$t"
          echo "semgrep rule test failed: $(basename "$fixture")" >&2
          exit 1
        }
      done

      dirs=()
      for d in ${builtins.concatStringsSep " " roots.dirs}; do
        dirs+=("$source_dir/$d")
      done

      semgrep \
        --config ${rulesFile} \
        --json \
        --metrics=off \
        --no-git-ignore \
        --jobs "$(nproc)" \
        --max-target-bytes 4000000 \
        --timeout 120 \
        "''${dirs[@]}" \
        > "$output_dir/report.json" 2> "$output_dir/scan-errors.txt" || {
          cat "$output_dir/scan-errors.txt" >&2
          echo "semgrep: scan failed" >&2
          exit 1
        }

      jq -esr -f ${./semgrep-report.jq} "$output_dir/report.json" \
        > "$output_dir/count.txt"
      warnings=$(jq '.errors | length' "$output_dir/report.json")
      if [ "$warnings" -gt 0 ]; then
        echo "PARTIAL COVERAGE: $warnings source parsing warnings; findings are incomplete" \
          | tee "$output_dir/coverage.txt" >&2
      else
        echo 'Complete scan: no source parsing warnings' > "$output_dir/coverage.txt"
      fi
      cat "$output_dir/coverage.txt" > "$output_dir/report.txt"
      jq -r '.results[] | "\(.path):\(.start.line): \(.check_id): \(.extra.message)"' \
        "$output_dir/report.json" >> "$output_dir/report.txt"
    '';
  };
in
mkSourceReport "semgrep" runner
