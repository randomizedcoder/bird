# shellcheck shell=bash
# fuzz-campaign: an unattended, resumable libFuzzer campaign over every
# harness (see ../fuzz.nix, which prepends the configuration and sources
# fuzz-common.sh).
#
#   fuzz-campaign [--hours H] [--jobs N] [--workdir DIR] [--harnesses "a b"]
#                 [--status-minutes M] [--min-free-gb G] [--rss-mb MB]
#
# Defaults: 12 hours, nproc - 2 jobs, ~/bird-fuzz, every harness, status
# every 15 minutes, stop if the work directory's file system has less than
# 10 GB free, 4096 MB per fuzzing process.
#
# DIR/<harness>/corpus is kept between runs, so a second campaign (or one
# restarted after an interruption) continues from the coverage already
# reached. Writes, while running:
#   DIR/status.txt     the latest progress table
#   DIR/history.csv    one row per harness per status interval
# and at the end (also after Ctrl-C / SIGTERM):
#   DIR/<harness>/repro/*.txt   symbolized reproduction of each saved input
#   DIR/<harness>/unique.txt    distinct crash signatures with counts
#   DIR/summary.txt             per-harness totals
# Each corpus is minimized at the end (-merge=1), unless --no-merge.
#
# To run detached and survive logout:
#   systemd-run --user --unit bird-fuzz -p RuntimeMaxSec=13h \
#     "$(command -v fuzz-campaign)" --hours 12
#   journalctl --user -u bird-fuzz -f ; cat ~/bird-fuzz/status.txt

hours=12
jobs=$(( $(nproc) - 2 ))
workdir="${HOME:-/tmp}/bird-fuzz"
harnesses="$FUZZ_ALL"
status_minutes=15
min_free_gb=10
rss_mb=4096
merge=1

usage() {
  sed -n '/^#   fuzz-campaign/,/^# Defaults/p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --hours) hours="$2"; shift 2 ;;
    --jobs) jobs="$2"; shift 2 ;;
    --workdir) workdir="$2"; shift 2 ;;
    --harnesses) harnesses="$2"; shift 2 ;;
    --status-minutes) status_minutes="$2"; shift 2 ;;
    --min-free-gb) min_free_gb="$2"; shift 2 ;;
    --rss-mb) rss_mb="$2"; shift 2 ;;
    --no-merge) merge=0; shift ;;
    -h|--help) usage 0 ;;
    *) echo "fuzz-campaign: unknown option $1" >&2; usage 2 ;;
  esac
done

[ "$jobs" -ge 1 ] || jobs=1
secs="$(awk -v h="$hours" 'BEGIN { s = int(h * 3600); print (s < 60) ? 60 : s }')"
interval=$(( status_minutes * 60 ))
[ "$interval" -ge 10 ] || interval=10

mkdir -p "$workdir"
workdir="$(cd "$workdir" && pwd)"
fuzz_env "$rss_mb"

free_gb() {
  df -P -B1G "$workdir" | awk 'NR == 2 { print $4 }'
}

if [ "$(free_gb)" -lt "$min_free_gb" ]; then
  echo "fuzz-campaign: less than ${min_free_gb} GB free in $workdir, not starting" >&2
  exit 1
fi

# Jobs per harness, proportional to fuzz_weight, at least 1 each.
declare -A forks
total_weight=0
for h in $harnesses; do
  total_weight=$(( total_weight + $(fuzz_weight "$h") ))
done
for h in $harnesses; do
  n=$(( jobs * $(fuzz_weight "$h") / total_weight ))
  forks[$h]=$(( n < 1 ? 1 : n ))
done

started="$(date -u +%FT%TZ)"
deadline=$(( $(date +%s) + secs ))
{
  echo "campaign started $started, ${secs}s, $jobs jobs, workdir $workdir"
  for h in $harnesses; do echo "  $h: ${forks[$h]} jobs"; done
} | tee "$workdir/campaign.txt"

[ -f "$workdir/history.csv" ] ||
  echo "time,harness,execs,cov,ft,corpus,exec_s,crash_files" > "$workdir/history.csv"

declare -A pids
for h in $harnesses; do
  dir="$workdir/$h"
  fuzz_prepare "$dir" "$h"
  echo "=== $started: -fork=${forks[$h]} -max_total_time=$secs" >> "$dir/fuzz.log"
  mapfile -t extra < <(fuzz_args "$h")
  (cd "$dir" && exec nice -n 10 "$root/bin/fuzz_$h" \
    -fork="${forks[$h]}" -max_total_time="$secs" "${extra[@]}" \
    -rss_limit_mb="$rss_mb" -malloc_limit_mb="$rss_mb" -timeout=25 \
    -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 \
    -artifact_prefix="$dir/crashes/" -print_final_stats=1 \
    "$dir/corpus" >> "$dir/fuzz.log" 2>&1) &
  pids[$h]=$!
done

write_status() {
  local now t h s
  now="$(date -u +%FT%TZ)"
  t="$workdir/status.txt.new"
  {
    echo "bird fuzz campaign: started $started, now $now, ends in $(( (deadline - $(date +%s)) / 60 )) min"
    printf '%-10s %5s %12s %7s %8s %8s %8s %7s\n' harness jobs execs cov ft corpus exec/s crashes
    for h in $harnesses; do
      read -r -a s <<< "$(fuzz_stats "$workdir/$h")"
      c="$(fuzz_crash_count "$workdir/$h")"
      printf '%-10s %5s %12s %7s %8s %8s %8s %7s\n' "$h" "${forks[$h]}" "${s[0]}" "${s[1]}" "${s[2]}" "${s[3]}" "${s[4]}" "$c"
      echo "$now,$h,${s[0]},${s[1]},${s[2]},${s[3]},${s[4]},$c" >> "$workdir/history.csv"
    done
    echo "free: $(free_gb) GB in $workdir"
  } > "$t"
  mv "$t" "$workdir/status.txt"
}

stop_all() {
  for h in $harnesses; do
    kill -INT "${pids[$h]}" 2>/dev/null || true
  done
}

interrupted=0
trap 'interrupted=1; stop_all' INT TERM

running() {
  for h in $harnesses; do
    kill -0 "${pids[$h]}" 2>/dev/null && return 0
  done
  return 1
}

next=$(( $(date +%s) + interval ))
while running; do
  sleep 10 || true
  [ "$interrupted" = 1 ] && break

  if [ "$(date +%s)" -ge "$next" ]; then
    write_status
    next=$(( $(date +%s) + interval ))
  fi

  if [ "$(free_gb)" -lt "$min_free_gb" ]; then
    echo "fuzz-campaign: less than ${min_free_gb} GB free, stopping early" | tee -a "$workdir/campaign.txt"
    stop_all
    break
  fi

  # libFuzzer stops itself at -max_total_time; this catches a stuck one.
  if [ "$(date +%s)" -gt $(( deadline + 900 )) ]; then
    echo "fuzz-campaign: past the deadline, stopping" | tee -a "$workdir/campaign.txt"
    stop_all
    break
  fi
done

# Give the fork-mode parents time to collect their jobs, then make sure.
for _ in $(seq 60); do running || break; sleep 2; done
for h in $harnesses; do kill -KILL "${pids[$h]}" 2>/dev/null || true; done
wait 2>/dev/null || true
trap - INT TERM
write_status

echo "campaign finished $(date -u +%FT%TZ) (interrupted: $interrupted); reproducing and merging" | tee -a "$workdir/campaign.txt"

summary="$workdir/summary.txt"
printf '%-10s %8s %8s %8s %12s %7s\n' harness corpus crashes unique execs cov > "$summary"
for h in $harnesses; do
  dir="$workdir/$h"
  fuzz_repro "$dir" "$h"
  u="$(fuzz_dedup "$dir")"

  if [ "$merge" = 1 ] && [ -d "$dir/corpus" ]; then
    rm -rf "$dir/corpus.min"
    mkdir -p "$dir/corpus.min"
    mapfile -t extra < <(fuzz_args "$h")
    if timeout 3600 "$root/bin/fuzz_$h" -merge=1 "${extra[@]}" -rss_limit_mb="$rss_mb" -timeout=25 \
        "$dir/corpus.min" "$dir/corpus" > "$dir/merge.log" 2>&1 &&
       [ -n "$(ls -A "$dir/corpus.min")" ]; then
      rm -rf "$dir/corpus.old"
      mv "$dir/corpus" "$dir/corpus.old"
      mv "$dir/corpus.min" "$dir/corpus"
      rm -rf "$dir/corpus.old"
    else
      echo "fuzz-campaign: $h: merge failed, corpus kept (see $dir/merge.log)" | tee -a "$workdir/campaign.txt"
      rm -rf "$dir/corpus.min"
    fi
  fi

  read -r -a s <<< "$(fuzz_stats "$dir")"
  printf '%-10s %8s %8s %8s %12s %7s\n' "$h" "$(find "$dir/corpus" -type f | wc -l)" \
    "$(fuzz_crash_count "$dir")" "$u" "${s[0]}" "${s[1]}" >> "$summary"
done

cat "$summary"
for h in $harnesses; do
  if [ -s "$workdir/$h/unique.txt" ]; then
    echo "--- $h"
    cat "$workdir/$h/unique.txt"
  fi
done
echo "$workdir"
