# shellcheck shell=bash
# fuzz-campaign: an unattended, resumable libFuzzer campaign over every
# harness (see ../fuzz.nix, which prepends the configuration and sources
# fuzz-common.sh).
#
#   fuzz-campaign [--hours H] [--jobs N] [--workdir DIR] [--harnesses "a b"]
#                 [--changed REF] [--plateau-minutes M] [--plateau-metric cov|ft]
#                 [--status-minutes M] [--min-free-gb G] [--rss-mb MB]
#
# Defaults: 12 hours, nproc - 2 jobs, ~/bird-fuzz, every harness, no
# plateau stop, status every 15 minutes, stop if the work directory's file
# system has less than 10 GB free, 4096 MB per fuzzing process.
#
# --changed REF keeps only the harnesses that cover a file changed since
# the merge base of REF and HEAD, uncommitted changes included, in the git
# checkout of the current directory (see fuzz_paths in ../fuzz.nix).
#
# --plateau-minutes M stops a harness once its coverage (cov, or with
# --plateau-metric ft the finer libFuzzer features) has not grown for M
# minutes. Its jobs go to the heaviest harness still running, which is
# restarted with them; the campaign ends when every harness has stopped.
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
changed=""
plateau_minutes=0
plateau_metric=cov
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
    --changed) changed="$2"; shift 2 ;;
    --plateau-minutes) plateau_minutes="$2"; shift 2 ;;
    --plateau-metric) plateau_metric="$2"; shift 2 ;;
    --status-minutes) status_minutes="$2"; shift 2 ;;
    --min-free-gb) min_free_gb="$2"; shift 2 ;;
    --rss-mb) rss_mb="$2"; shift 2 ;;
    --no-merge) merge=0; shift ;;
    -h|--help) usage 0 ;;
    *) echo "fuzz-campaign: unknown option $1" >&2; usage 2 ;;
  esac
done

[ "$jobs" -ge 1 ] || jobs=1
case "$plateau_metric" in
  cov|ft) ;;
  *) echo "fuzz-campaign: --plateau-metric is cov or ft" >&2; exit 2 ;;
esac
plateau=$(( plateau_minutes * 60 ))

# Does harness $1 cover file $2?
covers() {
  local h="$1" f="$2" p pats
  read -r -a pats <<< "$FUZZ_CORE_PATHS $(fuzz_paths "$h") nix/analysis/fuzz/fuzz_$h.c"
  for p in "${pats[@]}"; do
    # shellcheck disable=SC2053 # $p is a glob
    [[ $f == $p ]] && return 0
  done
  return 1
}

if [ -n "$changed" ]; then
  base="$(git merge-base "$changed" HEAD)" ||
    { echo "fuzz-campaign: no merge base of $changed and HEAD here" >&2; exit 2; }
  mapfile -t files < <(git diff --name-only "$base")
  picked=""
  for h in $harnesses; do
    for f in "${files[@]}"; do
      if covers "$h" "$f"; then picked="$picked $h"; break; fi
    done
  done
  harnesses="${picked# }"
  if [ -z "$harnesses" ]; then
    echo "fuzz-campaign: no harness covers the ${#files[@]} files changed since $changed"
    exit 0
  fi
  echo "fuzz-campaign: changes since $changed are covered by: $harnesses"
fi
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
used=0
for h in $harnesses; do
  n=$(( jobs * $(fuzz_weight "$h") / total_weight ))
  forks[$h]=$(( n < 1 ? 1 : n ))
  used=$(( used + forks[$h] ))
done
# Rounding down leaves jobs unused; hand them out heaviest harness first.
mapfile -t by_weight < <(for h in $harnesses; do echo "$(fuzz_weight "$h") $h"; done | sort -rn | cut -d' ' -f2)
i=0
while [ "$used" -lt "$jobs" ]; do
  h="${by_weight[i % ${#by_weight[@]}]}"
  forks[$h]=$(( forks[$h] + 1 ))
  used=$(( used + 1 ))
  i=$(( i + 1 ))
done

started="$(date -u +%FT%TZ)"
deadline=$(( $(date +%s) + secs ))
{
  echo "campaign started $started, ${secs}s, $jobs jobs, workdir $workdir"
  for h in $harnesses; do echo "  $h: ${forks[$h]} jobs"; done
} | tee "$workdir/campaign.txt"

[ -f "$workdir/history.csv" ] ||
  echo "time,harness,execs,cov,ft,corpus,exec_s,crash_files" > "$workdir/history.csv"

note() {
  echo "fuzz-campaign: $*" | tee -a "$workdir/campaign.txt"
}

# Run harness $1 for $2 seconds with forks[$1] jobs.
declare -A pids state best grown
start_harness() {
  local h="$1" left="$2" dir="$workdir/$1" extra
  echo "=== $(date -u +%FT%TZ): -fork=${forks[$h]} -max_total_time=$left" >> "$dir/fuzz.log"
  mapfile -t extra < <(fuzz_args "$h")
  (cd "$dir" && exec nice -n 10 "$root/bin/fuzz_$h" \
    -fork="${forks[$h]}" -max_total_time="$left" "${extra[@]}" \
    -rss_limit_mb="$rss_mb" -malloc_limit_mb="$rss_mb" -timeout=25 \
    -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 \
    -artifact_prefix="$dir/crashes/" -print_final_stats=1 \
    "$dir/corpus" >> "$dir/fuzz.log" 2>&1) &
  pids[$h]=$!
  state[$h]=run
}

# Stop harness $1, giving the fork-mode parent time to collect its jobs.
stop_harness() {
  local h="$1"
  kill -INT "${pids[$h]}" 2>/dev/null || true
  for _ in $(seq 60); do
    kill -0 "${pids[$h]}" 2>/dev/null || break
    sleep 2
  done
  kill -KILL "${pids[$h]}" 2>/dev/null || true
  wait "${pids[$h]}" 2>/dev/null || true
}

for h in $harnesses; do
  fuzz_prepare "$workdir/$h" "$h"
  start_harness "$h" "$secs"
  best[$h]=0
  grown[$h]=$(date +%s)
done

# Stop the harnesses whose coverage has not grown for $plateau seconds, and
# hand their jobs to the heaviest one still running.
check_plateau() {
  local now h s v x to left
  now=$(date +%s)
  for h in $harnesses; do
    [ "${state[$h]}" = run ] || continue
    read -r -a s <<< "$(fuzz_stats "$workdir/$h")"
    if [ "$plateau_metric" = ft ]; then v="${s[2]}"; else v="${s[1]}"; fi
    if [ "$v" -gt "${best[$h]}" ]; then
      best[$h]=$v
      grown[$h]=$now
      continue
    fi
    [ "${best[$h]}" -gt 0 ] && [ $(( now - grown[$h] )) -ge "$plateau" ] || continue

    note "$h: $plateau_metric stayed at ${best[$h]} for $plateau_minutes min, stopping"
    stop_harness "$h"
    state[$h]=plateau

    to=""
    for x in "${by_weight[@]}"; do
      if [ "${state[$x]}" = run ]; then to="$x"; break; fi
    done
    left=$(( deadline - $(date +%s) ))
    if [ -n "$to" ] && [ "$left" -ge 300 ]; then
      note "$to: restarting with ${forks[$h]} more jobs (from $h), $(( left / 60 )) min left"
      stop_harness "$to"
      forks[$to]=$(( forks[$to] + forks[$h] ))
      start_harness "$to" "$left"
    fi
    forks[$h]=0
  done
}

write_status() {
  local now t h s
  now="$(date -u +%FT%TZ)"
  t="$workdir/status.txt.new"
  {
    echo "bird fuzz campaign: started $started, now $now, ends in $(( (deadline - $(date +%s)) / 60 )) min"
    printf '%-10s %-7s %5s %12s %7s %8s %8s %8s %7s\n' harness state jobs execs cov ft corpus exec/s crashes
    for h in $harnesses; do
      read -r -a s <<< "$(fuzz_stats "$workdir/$h")"
      c="$(fuzz_crash_count "$workdir/$h")"
      printf '%-10s %-7s %5s %12s %7s %8s %8s %8s %7s\n' "$h" "${state[$h]}" "${forks[$h]}" "${s[0]}" "${s[1]}" "${s[2]}" "${s[3]}" "${s[4]}" "$c"
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
next_plateau=$(( $(date +%s) + 60 ))
while running; do
  sleep 10 || true
  [ "$interrupted" = 1 ] && break

  if [ "$plateau" -gt 0 ] && [ "$(date +%s)" -ge "$next_plateau" ]; then
    check_plateau
    next_plateau=$(( $(date +%s) + 60 ))
  fi

  if [ "$(date +%s)" -ge "$next" ]; then
    write_status
    next=$(( $(date +%s) + interval ))
  fi

  if [ "$(free_gb)" -lt "$min_free_gb" ]; then
    note "less than ${min_free_gb} GB free, stopping early"
    stop_all
    break
  fi

  # libFuzzer stops itself at -max_total_time; this catches a stuck one.
  if [ "$(date +%s)" -gt $(( deadline + 900 )) ]; then
    note "past the deadline, stopping"
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
