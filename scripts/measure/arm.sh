#!/bin/bash
# arm.sh <label> <src-store> <bindir> <outroot>
#
# One arm: copy a converted store, start a daemon on it, run three read
# commands against that one daemon, and leave behind
#   rss.txt     2 Hz RSS by executable path (epoch_ms comm pid rss_kb)
#   phases.txt  PHASE <name> <start|end> <epoch_ms> [rc=N]
#   daemon.log  the daemon's own debug log (authority open lines live here)
#   subject.txt what was actually run
#
# Every command's rc is captured on its own line before anything else can run,
# because a command substitution in a later argument resets $?.
set -u

label="${1:?label}"; src="${2:?src store}"; bindir="${3:?bindir}"; outroot="${4:?outroot}"
out="$outroot/$label"
mkdir -p "$out"

KIN="$bindir/kin"
KIND="$bindir/kin-daemon"
[ -x "$KIN" ]  || { echo "REFUSING: no executable kin at $KIN"; exit 64; }
[ -x "$KIND" ] || { echo "REFUSING: no executable kin-daemon at $KIND"; exit 64; }

# Subject proof, before the clock starts.
{
  echo "label      $label"
  echo "kin        $("$KIN" --version 2>&1 | head -1)"
  echo "kin sha256 $(shasum -a 256 "$KIN" | awk '{print $1}')"
  echo "kind sha256 $(shasum -a 256 "$KIND" | awk '{print $1}')"
  echo "src        $src"
  echo "started_utc $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$out/subject.txt"
cat "$out/subject.txt"

work="$out/work"
if [ ! -d "$work" ]; then
  echo "copying store..."
  cp -Rp "$src" "$work"; rc=$?
  [ "$rc" -eq 0 ] || { echo "REFUSING: store copy failed rc=$rc"; exit 65; }
fi
snap=$(ls -l "$work"/.kin/kindb/*/snapshots/*.kndb 2>/dev/null | awk '{print $5}' | head -1)
echo "snapshot_bytes $snap" >> "$out/subject.txt"
echo "snapshot_bytes $snap"

export KIN_HOME="$out/kinhome"
mkdir -p "$KIN_HOME"
export KIN_EMBED_BACKEND=cpu
export KIN_DAEMON_AUTO_EMBED=0
export RUST_LOG="kin_daemon=debug,kin_db=debug,kin_core=info"

stop="$out/stop"; rm -f "$stop"
: > "$out/phases.txt"

mark() { printf 'PHASE %s %s %s %s\n' "$1" "$2" "$(python3 -c 'import time;print(int(time.time()*1000))')" "${3:-}" >> "$out/phases.txt"; }

# 2 Hz RSS by EXECUTABLE PATH, so this arm's processes stay separate from the
# thirty other kin daemons on this box. One python3 per sample is the clock.
(
  while [ ! -f "$stop" ]; do
    now=$(python3 -c 'import time;print(int(time.time()*1000))')
    ps -Ao pid=,rss=,comm= | while read -r pid rss comm; do
      case "$comm" in
        "$bindir"*)
          base="${comm##*/}"
          case "$base" in
            kin|kin-daemon) printf '%s %s %s %s\n' "$now" "$base" "$pid" "$rss" >> "$out/rss.txt" ;;
          esac ;;
      esac
    done
    sleep 0.5
  done
) &
sampler=$!
echo "sampler pid $sampler"

cd "$work" || exit 66

mark daemon_start start
"$KIN" daemon start > "$out/daemon-start.txt" 2>&1; rc=$?
mark daemon_start end "rc=$rc"
echo "daemon start rc=$rc"

# Settle: let startup phases finish before the first read.
mark settle start
sleep 20
mark settle end "rc=0"

mark status1 start
"$KIN" graph status > "$out/status1.txt" 2>&1; rc=$?
mark status1 end "rc=$rc"
echo "status1 rc=$rc"

mark status2 start
"$KIN" graph status > "$out/status2.txt" 2>&1; rc=$?
mark status2 end "rc=$rc"
echo "status2 rc=$rc"

mark idle start
sleep 15
mark idle end "rc=0"

mark stop start
"$KIN" daemon stop > "$out/daemon-stop.txt" 2>&1; rc=$?
mark stop end "rc=$rc"
echo "daemon stop rc=$rc"

sleep 3
touch "$stop"
wait $sampler 2>/dev/null

cp -p "$work/.kin/daemon.log" "$out/daemon.log" 2>/dev/null
cp -p "$work/.kin/daemon-footprint" "$out/daemon-footprint" 2>/dev/null
cp -p "$work/.kin/daemon-boot-cost.json" "$out/daemon-boot-cost.json" 2>/dev/null

echo "ARM-COMPLETE $label"
