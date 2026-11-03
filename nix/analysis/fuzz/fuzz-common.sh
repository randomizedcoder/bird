# shellcheck shell=bash
# Shared by run-fuzzers and fuzz-campaign (sourced; see ../fuzz.nix).
#
# The caller defines, before sourcing:
#   root            the fuzz package (bin/, share/bird-fuzz/)
#   symbolizer      llvm-symbolizer path
# and these functions (generated from fuzz.nix):
#   fuzz_max_len NAME   largest useful input
#   fuzz_dict NAME      dictionary path, or empty
#
# Every function takes a harness directory DIR laid out as:
#   DIR/corpus/  DIR/crashes/  DIR/repro/  DIR/fuzz.log

# Sanitizer settings for fuzzing and reproduction. rss_mb also caps single
# allocations (malloc_limit_mb), so a bogus length fails as an OOM input.
fuzz_env() {
  local rss_mb="${1:-4096}"

  export ASAN_SYMBOLIZER_PATH="$symbolizer"
  export UBSAN_SYMBOLIZER_PATH="$symbolizer"
  export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=1:allocator_may_return_null=1:malloc_limit_mb=$rss_mb"
  export UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:print_stacktrace=1:symbolize=1:suppressions=$root/share/bird-fuzz/ubsan.supp"
}

# Create DIR and add the seeds of NAME to its corpus (existing files kept).
fuzz_prepare() {
  local dir="$1" name="$2"

  mkdir -p "$dir/corpus" "$dir/crashes" "$dir/repro"
  cp -n "$root/share/bird-fuzz/seeds/$name"/* "$dir/corpus/" 2>/dev/null || true
}

# libFuzzer options specific to NAME, one per line.
fuzz_args() {
  local name="$1" dict

  echo "-max_len=$(fuzz_max_len "$name")"
  dict="$(fuzz_dict "$name")"
  if [ -n "$dict" ]; then
    echo "-dict=$dict"
  fi
}

# Symbolized reproduction of each saved input not reproduced yet.
fuzz_repro() {
  local dir="$1" name="$2" c out

  for c in "$dir"/crashes/*; do
    [ -f "$c" ] || continue
    out="$dir/repro/$(basename "$c").txt"
    [ -s "$out" ] && continue
    timeout 300 "$root/bin/fuzz_$name" -runs=1 -timeout=60 "$c" > "$out" 2>&1 || true
  done
}

# One-line signature of a reproduction: the sanitizer SUMMARY (or libFuzzer
# deadly signal / timeout), plus the first three stack frames in BIRD code
# (not the sanitizer runtime, libFuzzer or libc).
fuzz_signature() {
  local repro="$1" summary frames

  summary="$(grep -m1 -aE '^SUMMARY: ' "$repro" | sed 's/^SUMMARY: //; s/ 0x[0-9a-f]*//g' || true)"
  if [ -z "$summary" ]; then
    summary="$(grep -m1 -aoE 'ERROR: libFuzzer: [a-z -]+|ALARM: working on the last Unit' "$repro" || true)"
  fi

  frames="$(grep -aE '^ +#[0-9]+ ' "$repro" |
    grep -avE '__sanitizer|__asan|__ubsan|fuzzer::|libc\.so|__libc_|_start|LLVMFuzzerTestOneInput|compiler-rt' |
    sed -E 's/^ +#[0-9]+ (0x[0-9a-f]+ in )?([^ ]+).*/\2/' | head -3 | paste -sd '<' - || true)"

  echo "${summary:-unknown} | ${frames:-no frames}"
}

# DIR/unique.txt: one line per distinct signature (count, signature, an
# example input). Prints the number of distinct signatures.
fuzz_dedup() {
  local dir="$1" r sig
  local tmp="$dir/.signatures"

  : > "$tmp"
  for r in "$dir"/repro/*.txt; do
    [ -f "$r" ] || continue
    sig="$(fuzz_signature "$r")"
    printf '%s\t%s\n' "$sig" "$(basename "$r" .txt)" >> "$tmp"
  done

  sort "$tmp" | awk -F'\t' '
    { n[$1]++; if (!($1 in ex)) ex[$1] = $2 }
    END { for (s in n) printf "%6d  %s  [%s]\n", n[s], s, ex[s] }' |
    sort -rn > "$dir/unique.txt"
  rm -f "$tmp"
  wc -l < "$dir/unique.txt"
}

# Latest libFuzzer progress of DIR as "execs cov ft corp exec_s"; fork mode
# prints "#N: cov: C ft: F corp: P exec/s: E ...", plain mode "#N ... cov: C
# ft: F corp: P/size ... exec/s: E".
fuzz_stats() {
  local dir="$1" line

  line="$(grep -aE '^#[0-9]+:? ' "$dir/fuzz.log" 2>/dev/null | grep -a 'cov:' | tail -1 || true)"
  if [ -z "$line" ]; then
    echo "0 0 0 0 0"
    return
  fi

  awk '{
    execs = $1; gsub(/[^0-9]/, "", execs)
    for (i = 1; i < NF; i++) {
      if ($i == "cov:") cov = $(i + 1)
      if ($i == "ft:") ft = $(i + 1)
      if ($i == "corp:") { corp = $(i + 1); sub(/\/.*/, "", corp) }
      if ($i == "exec/s:") es = $(i + 1)
    }
    printf "%s %s %s %s %s\n", execs, cov + 0, ft + 0, corp + 0, es + 0
  }' <<< "$line"
}

# Files in DIR/crashes (crash, timeout, oom and leak inputs).
fuzz_crash_count() {
  find "$1/crashes" -type f 2>/dev/null | wc -l
}
