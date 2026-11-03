# shellcheck shell=bash
# fuzz-coverage: source coverage reached by a corpus (see ../fuzz.nix, which
# prepends the configuration: root, llvm, src, FUZZ_ALL).
#
#   fuzz-coverage [WORKDIR] [OUTDIR]
#
# Replays WORKDIR/<harness>/corpus (a fuzz-campaign or run-fuzzers work
# directory; harnesses without one use their seeds) through the
# coverage-instrumented replay_* binaries, then writes to OUTDIR (default
# WORKDIR/coverage):
#   summary.txt         per-file line / function / region coverage, all harnesses
#   <harness>.txt       the same for one harness
#   functions.txt       functions never executed, by file (the next targets)
#   html/index.html     annotated sources

workdir="${1:-${HOME:-/tmp}/bird-fuzz}"
out="${2:-$workdir/coverage}"

mkdir -p "$out/profraw"
rm -f "$out"/profraw/*.profraw

objects=()
for h in $FUZZ_ALL; do
  corpus="$workdir/$h/corpus"
  [ -d "$corpus" ] || corpus="$root/share/bird-fuzz/seeds/$h"
  echo "fuzz-coverage: $h ($(find "$corpus" -type f | wc -l) inputs)"

  LLVM_PROFILE_FILE="$out/profraw/$h-%p.profraw" \
    timeout 7200 "$root/bin/replay_$h" "$corpus" > "$out/$h.replay.log" 2>&1 ||
    echo "fuzz-coverage: $h: replay exited $? (see $out/$h.replay.log)"

  if [ -n "$(find "$out/profraw" -name "$h-*.profraw" -print -quit)" ]; then
    "$llvm/bin/llvm-profdata" merge -sparse "$out"/profraw/"$h"-*.profraw -o "$out/$h.profdata"
    "$llvm/bin/llvm-cov" report -instr-profile="$out/$h.profdata" "$root/bin/replay_$h" \
      -ignore-filename-regex='nix/analysis/fuzz|/nix/store' > "$out/$h.txt" 2>/dev/null || true
    objects+=("$root/bin/replay_$h")
  fi
done

if [ ${#objects[@]} -eq 0 ]; then
  echo "fuzz-coverage: no profiles written" >&2
  exit 1
fi

"$llvm/bin/llvm-profdata" merge -sparse "$out"/profraw/*.profraw -o "$out/all.profdata"

cov_args=(-instr-profile="$out/all.profdata" "${objects[0]}")
for o in "${objects[@]:1}"; do
  cov_args+=(-object "$o")
done
# Stage 1 compiles in /build/source; fuzz_netlink.c #includes netlink.c from
# the stage-2 copy in /build/tree.
equiv_src="/build/source,$src"
equiv_tree="/build/tree,$src"
filter=(-ignore-filename-regex='nix/analysis/fuzz|/nix/store|test/'
  "-path-equivalence=$equiv_src" "-path-equivalence=$equiv_tree")

"$llvm/bin/llvm-cov" report "${cov_args[@]}" "${filter[@]}" > "$out/summary.txt"
"$llvm/bin/llvm-cov" show "${cov_args[@]}" "${filter[@]}" -format=html -output-dir="$out/html" \
  -show-line-counts-or-regions > /dev/null

# Functions with zero executions, in the protocol, nest and filter code.
"$llvm/bin/llvm-cov" export "${cov_args[@]}" "${filter[@]}" -format=text -skip-expansions |
  jq -r '.data[0].functions[] | select(.count == 0) |
         "\(.filenames[0] | sub("^/build/source/"; ""))\t\(.name)"' |
  grep -E '^(proto|nest|filter|lib|conf|sysdep)/' | sort -u |
  awk -F'\t' '$1 != f { f = $1; print f } { print "    " $2 }' > "$out/functions.txt"

tail -1 "$out/summary.txt"
echo "$out/html/index.html"
