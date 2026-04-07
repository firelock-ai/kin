#!/usr/bin/env bash
set -euo pipefail

show_help() {
  cat <<'USAGE'
Usage:
  scripts/profile-command.sh [options] -- <kin command...>

Options:
  -o, --out DIR              Output directory for the profiling bundle
  -c, --cwd DIR              Working directory for the profiled command
      --kin PATH             Kin binary to run
                             (default: target/release/kin, then kin)
      --sample-seconds N     Attach /usr/bin/sample for N seconds on macOS
                             (default: 30)
      --sample-interval N    Sample interval in ms for /usr/bin/sample
                             (default: 1)
      --resource-interval N  Seconds between resource snapshots while the
                             command runs (default: 1)
      --no-sample            Skip native stack sampling even on macOS
      --no-resources         Skip periodic resource snapshots
      --profile-summary      Ask Kin to print its built-in profile summary
  -h, --help                 Show this help

The wrapper always writes a Kin span profile JSON via `--profile-out` unless
the command already supplies one.

For repeated `locate` benchmarking over a query corpus, use
`scripts/profile_kin_command.py` with `--locate-corpus`.
USAGE
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
default_kin="$repo_root/target/release/kin"

out_dir=""
cwd="$(pwd)"
kin_bin=""
sample_seconds=30
sample_interval=1
resource_interval=1
want_sample=1
want_resources=1
profile_summary=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--out)
      out_dir="${2:-}"
      shift 2
      ;;
    -c|--cwd)
      cwd="${2:-}"
      shift 2
      ;;
    --kin)
      kin_bin="${2:-}"
      shift 2
      ;;
    --sample-seconds)
      sample_seconds="${2:-}"
      shift 2
      ;;
    --sample-interval)
      sample_interval="${2:-}"
      shift 2
      ;;
    --resource-interval)
      resource_interval="${2:-}"
      shift 2
      ;;
    --no-sample)
      want_sample=0
      shift
      ;;
    --no-resources)
      want_resources=0
      shift
      ;;
    --profile-summary)
      profile_summary=1
      shift
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Unknown option: $1" >&2
      show_help >&2
      exit 2
      ;;
  esac
done

if [[ $# -eq 0 ]]; then
  echo "Missing command. Pass the kin command after --." >&2
  show_help >&2
  exit 2
fi

if [[ -z "$out_dir" ]]; then
  stamp="$(date +%Y%m%d-%H%M%S)"
  out_dir="$repo_root/.kin-profile/$stamp"
fi

if [[ -z "$kin_bin" ]]; then
  if [[ -x "$default_kin" ]]; then
    kin_bin="$default_kin"
  else
    kin_bin="kin"
  fi
fi

mkdir -p "$out_dir"

stdout_file="$out_dir/stdout.log"
stderr_file="$out_dir/stderr.log"
resource_file="$out_dir/resources.log"
profile_file="$out_dir/kin-profile.json"
sample_file="$out_dir/sample.txt"
hardware_file="$out_dir/hardware.txt"
bundle_file="$out_dir/bundle.txt"
exit_file="$out_dir/exit.code"

cmd=("$@")
kin_name="$(basename "$kin_bin")"
if [[ "${#cmd[@]}" -gt 0 ]]; then
  case "${cmd[0]}" in
    kin|"$kin_name"|"$kin_bin")
      cmd=("${cmd[@]:1}")
      ;;
  esac
fi

if [[ "${#cmd[@]}" -eq 0 ]]; then
  echo "Missing Kin subcommand after an optional leading binary name." >&2
  exit 2
fi

has_profile_out=0
has_profile_summary=0
for arg in "${cmd[@]}"; do
  case "$arg" in
    --profile-out|--profile-out=*)
      has_profile_out=1
      ;;
    --profile-summary)
      has_profile_summary=1
      ;;
  esac
done

if [[ "$has_profile_out" -eq 0 ]]; then
  cmd+=(--profile-out "$profile_file")
fi
if [[ "$profile_summary" -eq 1 && "$has_profile_summary" -eq 0 ]]; then
  cmd+=(--profile-summary)
fi

{
  echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "cwd=$cwd"
  echo "kin_bin=$kin_bin"
  echo "out_dir=$out_dir"
  echo "profile_file=$profile_file"
  echo "stdout_file=$stdout_file"
  echo "stderr_file=$stderr_file"
  echo "resource_file=$resource_file"
  echo "sample_file=$sample_file"
  echo "sample_seconds=$sample_seconds"
  echo "sample_interval_ms=$sample_interval"
  echo "resource_interval_s=$resource_interval"
  printf 'command='
  printf '%q ' "${cmd[@]}"
  echo
} > "$bundle_file"

{
  echo "platform=$(uname -s)"
  echo "machine=$(uname -m)"
  echo
  echo "[sysctl]"
  sysctl hw.ncpu hw.physicalcpu hw.logicalcpu hw.memsize 2>/dev/null || true
  echo
  if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "[system_profiler SPDisplaysDataType]"
    system_profiler SPDisplaysDataType -detailLevel mini 2>/dev/null || true
  fi
} > "$hardware_file"

capture_resource_sample() {
  local pid="$1"
  local stamp
  local thread_count
  stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  thread_count="$(ps -M -p "$pid" 2>/dev/null | awk 'NR > 1 {count += 1} END {print count + 0}')"

  {
    echo "timestamp=$stamp"
    echo "pid=$pid"
    ps -o pid=,ppid=,pcpu=,rss=,vsz=,etime=,command= -p "$pid" 2>/dev/null || true
    echo "thread_count=$thread_count"
    echo "[memory_pressure]"
    memory_pressure -Q 2>/dev/null || true
    echo "[vm_stat]"
    vm_stat 2>/dev/null || true
    echo "[netstat]"
    netstat -ibn 2>/dev/null || true
    echo
  } >> "$resource_file"
}

command_pid=""
resource_pid=""
sample_pid=""
status=0

cleanup() {
  if [[ -n "${resource_pid:-}" ]] && kill -0 "$resource_pid" 2>/dev/null; then
    kill "$resource_pid" 2>/dev/null || true
  fi
  if [[ -n "${sample_pid:-}" ]] && kill -0 "$sample_pid" 2>/dev/null; then
    wait "$sample_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

cd "$cwd"
: > "$stdout_file"
: > "$stderr_file"
: > "$resource_file"

"$kin_bin" "${cmd[@]}" >"$stdout_file" 2>"$stderr_file" &
command_pid=$!

if [[ "$want_resources" -eq 1 ]]; then
  (
    while kill -0 "$command_pid" 2>/dev/null; do
      capture_resource_sample "$command_pid"
      sleep "$resource_interval"
    done
    capture_resource_sample "$command_pid"
  ) &
  resource_pid=$!
fi

if [[ "$want_sample" -eq 1 && "$(uname -s)" == "Darwin" ]]; then
  if command -v /usr/bin/sample >/dev/null 2>&1; then
    /usr/bin/sample "$command_pid" "$sample_seconds" "$sample_interval" -mayDie -fullPaths -f "$sample_file" >/dev/null 2>&1 &
    sample_pid=$!
  fi
fi

wait "$command_pid"
status=$?

if [[ -n "${resource_pid:-}" ]]; then
  wait "$resource_pid" 2>/dev/null || true
fi
if [[ -n "${sample_pid:-}" ]]; then
  wait "$sample_pid" 2>/dev/null || true
fi

printf '%s\n' "$status" > "$exit_file"

cat <<DONE
Profiling bundle written to: $out_dir
  kin profile: $profile_file
  stdout:      $stdout_file
  stderr:      $stderr_file
  resources:   $resource_file
  sample:      $sample_file
  hardware:    $hardware_file
  bundle:      $bundle_file
  exit code:   $exit_file
DONE

exit "$status"
