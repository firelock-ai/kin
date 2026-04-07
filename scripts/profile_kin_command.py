#!/usr/bin/env python3

import argparse
import csv
import dataclasses
import json
import os
import platform
import math
import re
import shlex
import subprocess
import sys
import threading
import time
import statistics
from pathlib import Path


def run_capture(cmd, timeout=5):
    return subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def parse_duration_limit(raw):
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)?\s*", str(raw))
    if not match:
        return 30.0
    value = float(match.group(1))
    unit = match.group(2) or "s"
    if unit == "ms":
        return value / 1000.0
    if unit == "m":
        return value * 60.0
    if unit == "h":
        return value * 3600.0
    return value


def percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = max(1, math.ceil((pct / 100.0) * len(ordered)))
    return ordered[min(rank - 1, len(ordered) - 1)]


def slugify(text, fallback="query"):
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", text.strip()).strip("-")
    return slug[:80] or fallback


def load_corpus(path):
    items = []
    with Path(path).open() as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            label = None
            query = line
            if "\t" in line:
                label, query = line.split("\t", 1)
                label = label.strip() or None
                query = query.strip()
            items.append(
                {
                    "label": label or slugify(query),
                    "query": query,
                }
            )
    return items


def parse_ps_time_to_ms(raw):
    raw = raw.strip()
    if not raw:
        return 0.0
    days = 0
    if "-" in raw:
        day_part, raw = raw.split("-", 1)
        try:
            days = int(day_part)
        except ValueError:
            days = 0
    parts = raw.split(":")
    try:
        if len(parts) == 3:
            hours = int(parts[0])
            minutes = int(parts[1])
            seconds = float(parts[2])
        elif len(parts) == 2:
            hours = 0
            minutes = int(parts[0])
            seconds = float(parts[1])
        else:
            hours = 0
            minutes = 0
            seconds = float(parts[0])
    except ValueError:
        return 0.0
    total_seconds = days * 86400 + hours * 3600 + minutes * 60 + seconds
    return total_seconds * 1000.0


def parse_scaled_bytes(raw):
    raw = raw.strip()
    if not raw:
        return 0
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([KMGTP]?)", raw, re.IGNORECASE)
    if not match:
        return 0
    value = float(match.group(1))
    suffix = match.group(2).upper()
    scale = {
        "": 1,
        "K": 1024,
        "M": 1024**2,
        "G": 1024**3,
        "T": 1024**4,
        "P": 1024**5,
    }[suffix]
    return int(value * scale)


def read_sysctl(name):
    result = run_capture(["sysctl", "-n", name], timeout=2)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def extract_pct(line, label):
    prefix = line.split(label, 1)[0]
    prefix = prefix.strip().rstrip("%")
    token = prefix.split()[-1] if prefix.split() else "0"
    try:
        return float(token)
    except ValueError:
        return 0.0


def parse_top_cpu_pct(text):
    for line in text.splitlines():
        if line.startswith("CPU usage:"):
            user = extract_pct(line, "user")
            sys_pct = extract_pct(line, "sys")
            return round(user + sys_pct, 3)
    return None


def parse_load_avg(text):
    raw = text.strip()
    if not raw:
        return None, None
    if ":" in raw:
        raw = raw.split(":", 1)[1]
    raw = raw.replace("{", " ").replace("}", " ").replace(",", " ")
    parts = [part for part in raw.split() if part]
    try:
        values = [float(part) for part in parts]
    except ValueError:
        return None, None
    if len(values) >= 2:
        return values[0], values[1]
    return None, None


def parse_network_totals(text):
    for line in text.splitlines():
        if line.startswith("Networks:"):
            match = re.search(
                r"packets:\s+\d+/([0-9.]+[KMGTP]?)\s+in,\s+\d+/([0-9.]+[KMGTP]?)\s+out",
                line,
            )
            if match:
                return {
                    "total_in_bytes": parse_scaled_bytes(match.group(1)),
                    "total_out_bytes": parse_scaled_bytes(match.group(2)),
                }
    return None


def parse_vm_stat(text):
    lines = text.splitlines()
    if not lines:
        return None
    page_size_match = re.search(r"page size of (\d+) bytes", lines[0])
    page_size = int(page_size_match.group(1)) if page_size_match else 16384

    def page_value(prefix):
        for line in lines:
            if line.startswith(prefix):
                value = line.split(":", 1)[1].strip().rstrip(".")
                try:
                    return int(value)
                except ValueError:
                    return 0
        return 0

    free = page_value("Pages free")
    active = page_value("Pages active")
    inactive = page_value("Pages inactive")
    speculative = page_value("Pages speculative")
    wired = page_value("Pages wired down")
    compressed = page_value("Pages occupied by compressor")
    used_pages = active + wired + compressed
    available_pages = free + inactive + speculative

    mem_used_bytes = used_pages * page_size
    mem_available_bytes = available_pages * page_size
    total = mem_used_bytes + mem_available_bytes
    mem_pressure_pct = round((mem_used_bytes / total) * 100.0, 3) if total else 0.0

    return {
        "mem_used_bytes": mem_used_bytes,
        "mem_available_bytes": mem_available_bytes,
        "mem_pressure_pct": mem_pressure_pct,
    }


def parse_swap_usage(raw):
    used_match = re.search(r"used\s*=\s*([0-9.]+)M", raw)
    total_match = re.search(r"total\s*=\s*([0-9.]+)M", raw)
    used = int(float(used_match.group(1)) * 1024 * 1024) if used_match else 0
    total = int(float(total_match.group(1)) * 1024 * 1024) if total_match else 0
    return {
        "swap_used_bytes": used,
        "swap_total_bytes": total,
    }


def detect_baseline():
    baseline = {
        "os": platform.platform(),
        "arch": platform.machine(),
        "logical_cores": 0,
        "physical_cores": 0,
        "performance_cores": None,
        "efficiency_cores": None,
        "memory_bytes": 0,
        "gpu_models": [],
    }
    logical = read_sysctl("hw.logicalcpu") or read_sysctl("hw.ncpu")
    physical = read_sysctl("hw.physicalcpu")
    memory = read_sysctl("hw.memsize")
    perf = read_sysctl("hw.perflevel0.physicalcpu")
    eff = read_sysctl("hw.perflevel1.physicalcpu")
    try:
        baseline["logical_cores"] = int(logical or 0)
    except ValueError:
        pass
    try:
        baseline["physical_cores"] = int(physical or 0)
    except ValueError:
        pass
    try:
        baseline["memory_bytes"] = int(memory or 0)
    except ValueError:
        pass
    if perf is not None:
        try:
            baseline["performance_cores"] = int(perf)
        except ValueError:
            pass
    if eff is not None:
        try:
            baseline["efficiency_cores"] = int(eff)
        except ValueError:
            pass

    if sys.platform == "darwin":
        profiler = run_capture(["system_profiler", "SPDisplaysDataType"], timeout=15)
        gpu_models = []
        if profiler.returncode == 0:
            for line in profiler.stdout.splitlines():
                if "Chipset Model:" in line:
                    gpu_models.append(line.split(":", 1)[1].strip())
        baseline["gpu_models"] = gpu_models

    return baseline


def capture_system_snapshot():
    top_out = run_capture(["top", "-l", "1", "-n", "0", "-s", "0"], timeout=5)
    vm_out = run_capture(["vm_stat"], timeout=5)
    swap_raw = read_sysctl("vm.swapusage") or ""
    load_raw = read_sysctl("vm.loadavg") or ""

    snapshot = {
        "cpu_pct": None,
        "load_avg_1m": None,
        "load_avg_5m": None,
        "mem_used_bytes": None,
        "mem_available_bytes": None,
        "mem_pressure_pct": None,
        "swap_used_bytes": None,
        "swap_total_bytes": None,
        "system_network": None,
    }

    if top_out.returncode == 0:
        snapshot["cpu_pct"] = parse_top_cpu_pct(top_out.stdout)
        snapshot["system_network"] = parse_network_totals(top_out.stdout)
    if vm_out.returncode == 0:
        snapshot.update(parse_vm_stat(vm_out.stdout) or {})
    if load_raw:
        load_1m, load_5m = parse_load_avg(load_raw)
        snapshot["load_avg_1m"] = load_1m
        snapshot["load_avg_5m"] = load_5m
    if swap_raw:
        snapshot.update(parse_swap_usage(swap_raw))
    return snapshot


def capture_process_snapshot(pid):
    process = {
        "cpu_pct": None,
        "rss_bytes": None,
        "cpu_time_ms": None,
        "thread_count": None,
        "threads": [],
        "network": None,
    }

    top_out = run_capture(
        ["top", "-l", "1", "-pid", str(pid), "-stats", "pid,command,cpu,threads,mem,time"],
        timeout=5,
    )
    if top_out.returncode == 0:
        for line in reversed(top_out.stdout.splitlines()):
            stripped = line.strip()
            if not stripped or not re.match(r"^\d+\s+", stripped):
                continue
            tokens = stripped.split()
            if len(tokens) >= 6:
                try:
                    process["cpu_pct"] = float(tokens[2])
                except ValueError:
                    pass
                process["rss_bytes"] = parse_scaled_bytes(tokens[4])
                process["cpu_time_ms"] = parse_ps_time_to_ms(tokens[5])
                try:
                    process["thread_count"] = int(tokens[3])
                except ValueError:
                    pass
            break

    ps_out = run_capture(["ps", "-o", "pcpu=,rss=,time=", "-p", str(pid)], timeout=3)
    if ps_out.returncode == 0:
        tokens = ps_out.stdout.split()
        if len(tokens) >= 3:
            try:
                process["cpu_pct"] = float(tokens[0])
            except ValueError:
                pass
            try:
                rss_from_ps = int(tokens[1]) * 1024
                if not process["rss_bytes"]:
                    process["rss_bytes"] = rss_from_ps
            except ValueError:
                pass
            if process["cpu_time_ms"] is None:
                process["cpu_time_ms"] = parse_ps_time_to_ms(tokens[2])

    thread_out = run_capture(["ps", "-M", "-p", str(pid), "-o", "pid,pcpu,time,state,comm"], timeout=3)
    thread_rows = []
    if thread_out.returncode == 0:
        for line in thread_out.stdout.splitlines()[1:]:
            match = re.search(r"(\d+)\s+([0-9.]+)\s+([0-9:.\-]+)\s+([A-Z?]+)\s+(\S+)\s*$", line)
            if not match:
                continue
            thread_rows.append(
                {
                    "thread_slot": len(thread_rows),
                    "identifier": int(match.group(1)),
                    "cpu_pct": float(match.group(2)),
                    "cpu_time_ms": parse_ps_time_to_ms(match.group(3)),
                    "state": match.group(4),
                    "command": match.group(5),
                }
            )
    process["threads"] = thread_rows
    if process["thread_count"] is None:
        process["thread_count"] = len(thread_rows)
    return process


def capture_process_network(pid):
    if sys.platform != "darwin":
        return None
    result = run_capture(
        ["nettop", "-P", "-x", "-L", "1", "-p", str(pid), "-j", "bytes_in,bytes_out"],
        timeout=4,
    )
    if result.returncode != 0:
        return None

    rows = list(csv.reader(result.stdout.splitlines()))
    if len(rows) < 2:
        return None
    header = rows[0]
    try:
        bytes_in_idx = header.index("bytes_in")
        bytes_out_idx = header.index("bytes_out")
    except ValueError:
        return None

    for row in rows[1:]:
        if len(row) <= max(bytes_in_idx, bytes_out_idx):
            continue
        try:
            return {
                "bytes_in": int(float(row[bytes_in_idx] or "0")),
                "bytes_out": int(float(row[bytes_out_idx] or "0")),
            }
        except ValueError:
            continue
    return None


class ResourceSampler:
    def __init__(self, pid, interval_ms, network_enabled):
        self.pid = pid
        self.interval_ms = interval_ms
        self.network_enabled = network_enabled
        self.baseline = detect_baseline()
        self.started_at = time.time()
        self._samples = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="kin-resource-sampler", daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=10)
        return {
            "format": "kin.resource_profile.v1",
            "baseline": self.baseline,
            "samples": self._samples,
        }

    def _run(self):
        while not self._stop.is_set():
            offset_ms = int((time.time() - self.started_at) * 1000)
            system_snapshot = capture_system_snapshot()
            process_snapshot = capture_process_snapshot(self.pid)
            if self.network_enabled:
                process_snapshot["network"] = capture_process_network(self.pid)
            self._samples.append(
                {
                    "offset_ms": offset_ms,
                    "system": system_snapshot,
                    "process": process_snapshot,
                }
            )
            self._stop.wait(self.interval_ms / 1000.0)


def tee_stream(stream, destination, mirror):
    try:
        for line in iter(stream.readline, ""):
            destination.write(line)
            destination.flush()
            mirror.write(line)
            mirror.flush()
    finally:
        stream.close()


def ensure_profile_out(command, kin_profile_path, inject):
    if not inject:
        return command
    if "--profile-out" in command:
        return command
    if command and Path(command[0]).name == "kin":
        return [command[0], "--profile-out", str(kin_profile_path), *command[1:]]
    return command + ["--profile-out", str(kin_profile_path)]


def start_sample(pid, sample_path, duration_sec, interval_ms):
    if sys.platform != "darwin":
        return None
    cmd = [
        "sample",
        str(pid),
        str(duration_sec),
        str(interval_ms),
        "-mayDie",
        "-file",
        str(sample_path),
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_xctrace(pid, bundle_dir, template, time_limit):
    if sys.platform != "darwin":
        return None, None
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", template.lower()).strip("-") or "xctrace"
    trace_dir = bundle_dir / "xctrace"
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_path = trace_dir / f"{safe_name}.trace"
    proc = subprocess.Popen(
        [
            "xctrace",
            "record",
            "--output",
            str(trace_path),
            "--template",
            template,
            "--attach",
            str(pid),
            "--time-limit",
            str(time_limit),
            "--no-prompt",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc, trace_path


def wait_with_timeout(proc, timeout):
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
    return {
        "returncode": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
    }


def load_json(path):
    if not path.exists():
        return None
    with path.open() as handle:
        return json.load(handle)


def summarize_kin_profile(report):
    if not report:
        return None
    summary = report.get("summary", {})
    return {
        "total_ms": report.get("total_ms"),
        "span_count": report.get("span_count"),
        "hot_paths": summary.get("hot_paths", [])[:15],
        "slowest_spans": summary.get("slowest_spans", [])[:15],
    }


def summarize_sample_output(path):
    if not path.exists():
        return None
    text = path.read_text(errors="replace")
    lines = text.splitlines()
    in_section = False
    frames = []
    for line in lines:
        if line.startswith("Sort by top of stack"):
            in_section = True
            continue
        if in_section:
            if not line.strip():
                continue
            if line.startswith("Binary Images:"):
                break
            match = re.match(r"\s*(.*?)\s+(\d+)\s*$", line)
            if match:
                frames.append(
                    {
                        "symbol": match.group(1).strip(),
                        "samples": int(match.group(2)),
                    }
                )
    return frames[:20]


def summarize_resources(resource_report):
    if not resource_report:
        return None
    samples = resource_report.get("samples", [])
    if not samples:
        return {
            "peak_process_rss_bytes": 0,
            "peak_process_cpu_pct": 0.0,
            "peak_thread_count": 0,
            "peak_system_cpu_pct": 0.0,
            "peak_mem_pressure_pct": 0.0,
            "peak_process_network_in_bytes": 0,
            "peak_process_network_out_bytes": 0,
        }

    def max_value(path):
        best = None
        for sample in samples:
            current = sample
            for key in path:
                if current is None:
                    break
                current = current.get(key)
            if current is None:
                continue
            best = current if best is None else max(best, current)
        return best or 0

    return {
        "peak_process_rss_bytes": max_value(["process", "rss_bytes"]),
        "peak_process_cpu_pct": max_value(["process", "cpu_pct"]),
        "peak_thread_count": max_value(["process", "thread_count"]),
        "peak_system_cpu_pct": max_value(["system", "cpu_pct"]),
        "peak_mem_pressure_pct": max_value(["system", "mem_pressure_pct"]),
        "peak_process_network_in_bytes": max_value(["process", "network", "bytes_in"]),
        "peak_process_network_out_bytes": max_value(["process", "network", "bytes_out"]),
    }


def emit_trace_viewer(bundle_dir, command, pid, kin_profile, resource_report):
    trace_path = bundle_dir / "timeline.trace.json"
    events = [
        {
            "ph": "M",
            "pid": pid,
            "tid": 0,
            "name": "process_name",
            "args": {"name": Path(command[0]).name if command else "command"},
        },
        {
            "ph": "M",
            "pid": 0,
            "tid": 0,
            "name": "process_name",
            "args": {"name": "system"},
        },
    ]

    if kin_profile:
        for span in kin_profile.get("spans", []):
            events.append(
                {
                    "ph": "X",
                    "pid": pid,
                    "tid": 0,
                    "name": span.get("name", "span"),
                    "cat": span.get("target", "kin"),
                    "ts": int(float(span.get("started_ms", 0.0)) * 1000.0),
                    "dur": int(float(span.get("duration_ms", 0.0)) * 1000.0),
                    "args": {
                        "path": span.get("path"),
                        "self_ms": span.get("self_ms"),
                        "fields": span.get("fields", {}),
                    },
                }
            )

    for sample in resource_report.get("samples", []):
        offset_us = int(sample.get("offset_ms", 0)) * 1000
        process = sample.get("process", {})
        system = sample.get("system", {})
        events.append(
            {
                "ph": "C",
                "pid": pid,
                "tid": 1,
                "name": "process.resources",
                "ts": offset_us,
                "args": {
                    "cpu_pct": process.get("cpu_pct") or 0.0,
                    "rss_bytes": process.get("rss_bytes") or 0,
                    "thread_count": process.get("thread_count") or 0,
                    "cpu_time_ms": process.get("cpu_time_ms") or 0.0,
                    "net_in_bytes": (process.get("network") or {}).get("bytes_in", 0),
                    "net_out_bytes": (process.get("network") or {}).get("bytes_out", 0),
                },
            }
        )
        events.append(
            {
                "ph": "C",
                "pid": 0,
                "tid": 0,
                "name": "system.resources",
                "ts": offset_us,
                "args": {
                    "cpu_pct": system.get("cpu_pct") or 0.0,
                    "mem_pressure_pct": system.get("mem_pressure_pct") or 0.0,
                    "swap_used_bytes": system.get("swap_used_bytes") or 0,
                    "load_avg_1m": system.get("load_avg_1m") or 0.0,
                    "load_avg_5m": system.get("load_avg_5m") or 0.0,
                    "net_in_bytes": (system.get("system_network") or {}).get("total_in_bytes", 0),
                    "net_out_bytes": (system.get("system_network") or {}).get("total_out_bytes", 0),
                },
            }
        )

    events.sort(key=lambda item: (item.get("ts", 0), item.get("name", "")))
    with trace_path.open("w") as handle:
        json.dump({"traceEvents": events, "displayTimeUnit": "ms"}, handle, indent=2)
    return trace_path


def write_summary(bundle_dir, manifest):
    summary_path = bundle_dir / "summary.md"
    with summary_path.open("w") as handle:
        handle.write("# Kin Performance Profile\n\n")
        handle.write(f"- Command: `{shlex.join(manifest['command'])}`\n")
        if manifest.get("mode") == "benchmark":
            handle.write(f"- Corpus: `{manifest.get('corpus_path')}`\n")
            handle.write(f"- Repeats: `{manifest.get('repeats')}`\n")
            handle.write(f"- Warmups: `{manifest.get('warmups')}`\n")
        handle.write(f"- Exit code: `{manifest['exit_code']}`\n")
        handle.write(f"- Command duration: `{manifest['duration_ms']}` ms\n")
        handle.write(f"- Bundle duration: `{manifest['bundle_duration_ms']}` ms\n")

        peaks = manifest["summary"].get("resource_peaks") or {}
        if peaks:
            handle.write("\n## Resource peaks\n\n")
            for key, value in peaks.items():
                handle.write(f"- `{key}`: `{value}`\n")

        benchmark = manifest["summary"].get("benchmark")
        if benchmark:
            handle.write("\n## Locate benchmark\n\n")
            handle.write(
                f"- Runs: `{benchmark['measurement_runs']}` measured, `{benchmark['warmup_runs']}` warmups\n"
            )
            handle.write(
                f"- Wall time median / p95: `{benchmark['duration_ms']['median']}` ms / `{benchmark['duration_ms']['p95']}` ms\n"
            )
            handle.write(
                f"- Kin span median / p95: `{benchmark['kin_profile_total_ms']['median']}` ms / `{benchmark['kin_profile_total_ms']['p95']}` ms\n"
            )
            handle.write(
                f"- Peak RSS median / p95: `{benchmark['peak_process_rss_bytes']['median']}` / `{benchmark['peak_process_rss_bytes']['p95']}` bytes\n"
            )
            if benchmark.get("queries"):
                handle.write("\n### Per-query summary\n\n")
                for query in benchmark["queries"]:
                    handle.write(
                        f"- `{query['label']}`: wall median `{query['duration_ms']['median']}` ms, wall p95 `{query['duration_ms']['p95']}` ms, kin median `{query['kin_profile_total_ms']['median']}` ms, kin p95 `{query['kin_profile_total_ms']['p95']}` ms\n"
                    )

        kin_profile = manifest["summary"].get("kin_profile")
        if kin_profile:
            handle.write("\n## Hottest Kin spans\n\n")
            for hot in kin_profile.get("hot_paths", [])[:10]:
                handle.write(
                    f"- `{hot.get('path')}`: self `{hot.get('self_ms')}` ms, total `{hot.get('total_ms')}` ms, count `{hot.get('count')}`\n"
                )

        sample_frames = manifest["summary"].get("sample_top_frames")
        if sample_frames:
            handle.write("\n## Top sampled frames\n\n")
            for frame in sample_frames[:10]:
                handle.write(f"- `{frame['symbol']}`: `{frame['samples']}` samples\n")

        trace_json = manifest["artifacts"].get("trace_viewer")
        if trace_json:
            handle.write("\n## Timeline\n\n")
            handle.write(f"- Open `{trace_json}` in Perfetto or `chrome://tracing`.\n")


@dataclasses.dataclass
class RunResult:
    manifest: dict
    bundle_dir: Path


def run_profile_bundle(command, cwd, bundle_dir, args, inject_profile_out=True, emit_summary=True):
    bundle_dir = Path(bundle_dir).resolve()
    bundle_dir.mkdir(parents=True, exist_ok=True)

    kin_profile_path = bundle_dir / "kin-profile.json"
    resource_report_path = bundle_dir / "resource-report.json"
    sample_path = bundle_dir / "sample.txt"
    stdout_path = bundle_dir / "stdout.log"
    stderr_path = bundle_dir / "stderr.log"
    manifest_path = bundle_dir / "manifest.json"

    profiled_command = ensure_profile_out(command, kin_profile_path, inject_profile_out)

    started_at = time.time()
    process = subprocess.Popen(
        profiled_command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )

    stdout_handle = stdout_path.open("w")
    stderr_handle = stderr_path.open("w")
    stdout_thread = threading.Thread(
        target=tee_stream,
        args=(process.stdout, stdout_handle, sys.stdout),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=tee_stream,
        args=(process.stderr, stderr_handle, sys.stderr),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    sampler = ResourceSampler(process.pid, args.resource_interval_ms, not args.no_network)
    sampler.start()
    sample_proc = None
    if not args.no_sample:
        sample_proc = start_sample(
            process.pid,
            sample_path,
            args.sample_duration_sec,
            args.sample_interval_ms,
        )

    xctrace_runs = []
    xctrace_procs = []
    for template in args.xctrace_template:
        proc, trace_path = start_xctrace(process.pid, bundle_dir, template, args.xctrace_time_limit)
        if proc is None:
            continue
        xctrace_procs.append((template, proc, trace_path))

    exit_code = process.wait()
    command_duration_ms = int((time.time() - started_at) * 1000)
    stdout_thread.join(timeout=10)
    stderr_thread.join(timeout=10)
    stdout_handle.close()
    stderr_handle.close()

    resource_report = sampler.stop()
    with resource_report_path.open("w") as handle:
        json.dump(resource_report, handle, indent=2)

    if sample_proc is not None:
        try:
            sample_proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            sample_proc.terminate()
            try:
                sample_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                sample_proc.kill()

    for template, proc, trace_path in xctrace_procs:
        capture = wait_with_timeout(proc, parse_duration_limit(args.xctrace_time_limit) + 10.0)
        toc_path = trace_path.with_suffix(".toc.xml")
        export_meta = None
        if trace_path.exists():
            export = run_capture(
                ["xctrace", "export", "--input", str(trace_path), "--toc", "--output", str(toc_path)],
                timeout=20,
            )
            export_meta = {
                "returncode": export.returncode,
                "stdout": export.stdout,
                "stderr": export.stderr,
                "toc_path": toc_path.name if toc_path.exists() else None,
            }
        xctrace_runs.append(
            {
                "template": template,
                "trace_path": trace_path.name if trace_path.exists() else None,
                "capture": capture,
                "export": export_meta,
            }
        )

    bundle_duration_ms = int((time.time() - started_at) * 1000)
    kin_profile = load_json(kin_profile_path)
    sample_summary = summarize_sample_output(sample_path)
    resource_summary = summarize_resources(resource_report)
    trace_viewer_path = emit_trace_viewer(bundle_dir, profiled_command, process.pid, kin_profile, resource_report)

    manifest = {
        "format": "kin.performance_bundle.v1",
        "mode": "single",
        "command": profiled_command,
        "cwd": str(Path(cwd).resolve()),
        "started_at_unix": started_at,
        "duration_ms": command_duration_ms,
        "bundle_duration_ms": bundle_duration_ms,
        "exit_code": exit_code,
        "artifacts": {
            "kin_profile": kin_profile_path.name if kin_profile_path.exists() else None,
            "resource_report": resource_report_path.name,
            "sample": sample_path.name if sample_path.exists() else None,
            "stdout": stdout_path.name,
            "stderr": stderr_path.name,
            "trace_viewer": trace_viewer_path.name if trace_viewer_path.exists() else None,
            "xctrace": xctrace_runs,
        },
        "summary": {
            "kin_profile": summarize_kin_profile(kin_profile),
            "sample_top_frames": sample_summary,
            "resource_peaks": resource_summary,
        },
        "limitations": [
            "Per-process GPU utilization is not emitted as structured JSON here. Use the optional xctrace output for Time Profiler or Metal System Trace when GPU activity matters.",
            "Per-core CPU utilization is not emitted on macOS in this script; aggregate system CPU, process CPU, thread count, thread snapshots, memory pressure, and process network IO are recorded instead.",
        ],
    }

    with manifest_path.open("w") as handle:
        json.dump(manifest, handle, indent=2)
    if emit_summary:
        write_summary(bundle_dir, manifest)

    return RunResult(manifest=manifest, bundle_dir=bundle_dir)


def replace_query_placeholder(command, query):
    placeholder = "__QUERY__"
    if placeholder in command:
        return [query if arg == placeholder else arg for arg in command]
    if any(Path(arg).name == "locate" for arg in command):
        return [*command, query]
    return [*command, query]


def extract_run_metrics(manifest):
    summary = manifest.get("summary", {})
    resource_peaks = summary.get("resource_peaks") or {}
    kin_profile = summary.get("kin_profile") or {}
    return {
        "duration_ms": manifest.get("duration_ms"),
        "kin_profile_total_ms": kin_profile.get("total_ms"),
        "peak_process_rss_bytes": resource_peaks.get("peak_process_rss_bytes"),
        "peak_process_cpu_pct": resource_peaks.get("peak_process_cpu_pct"),
        "peak_thread_count": resource_peaks.get("peak_thread_count"),
        "peak_system_cpu_pct": resource_peaks.get("peak_system_cpu_pct"),
    }


def normalize_stat(values):
    cleaned = [value for value in values if isinstance(value, (int, float))]
    if not cleaned:
        return {"median": None, "p95": None, "min": None, "max": None}
    return {
        "median": round(statistics.median(cleaned), 3),
        "p95": round(percentile(cleaned, 95), 3),
        "min": round(min(cleaned), 3),
        "max": round(max(cleaned), 3),
    }


def run_locate_corpus(command, cwd, bundle_dir, args):
    corpus = load_corpus(args.locate_corpus)
    if not corpus:
        raise SystemExit(f"corpus file is empty: {args.locate_corpus}")

    bundle_dir = Path(bundle_dir).resolve()
    bundle_dir.mkdir(parents=True, exist_ok=True)
    runs_dir = bundle_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    warmup_runs = max(args.locate_warmups, 0)
    measurement_runs = max(args.locate_repeats, 1)
    all_run_entries = []
    query_entries = []
    run_index = 0
    exit_code = 0

    for entry in corpus:
        query_runs = []
        for warmup_index in range(warmup_runs):
            warmup_command = replace_query_placeholder(command, entry["query"])
            warmup_dir = runs_dir / f"{run_index:03d}-{slugify(entry['label'])}-warmup-{warmup_index + 1:02d}"
            warmup_result = run_profile_bundle(
                warmup_command,
                cwd,
                warmup_dir,
                args,
                inject_profile_out=True,
                emit_summary=False,
            )
            if warmup_result.manifest.get("exit_code", 0) != 0 and exit_code == 0:
                exit_code = int(warmup_result.manifest.get("exit_code", 0) or 1)
        for repeat_index in range(measurement_runs):
            run_command = replace_query_placeholder(command, entry["query"])
            run_dir = runs_dir / f"{run_index:03d}-{slugify(entry['label'])}-run-{repeat_index + 1:02d}"
            result = run_profile_bundle(run_command, cwd, run_dir, args, inject_profile_out=True)
            metrics = extract_run_metrics(result.manifest)
            if result.manifest.get("exit_code", 0) != 0 and exit_code == 0:
                exit_code = int(result.manifest.get("exit_code", 0) or 1)
            query_runs.append(
                {
                    "run_dir": str(run_dir),
                    "metrics": metrics,
                    "exit_code": result.manifest.get("exit_code"),
                }
            )
            all_run_entries.append(
                {
                    "label": entry["label"],
                    "query": entry["query"],
                    "run_dir": str(run_dir),
                    "metrics": metrics,
                    "exit_code": result.manifest.get("exit_code"),
                }
            )
        query_entries.append(
            {
                "label": entry["label"],
                "query": entry["query"],
                "runs": query_runs,
                "duration_ms": normalize_stat([run["metrics"]["duration_ms"] for run in query_runs]),
                "kin_profile_total_ms": normalize_stat(
                    [run["metrics"]["kin_profile_total_ms"] for run in query_runs]
                ),
                "peak_process_rss_bytes": normalize_stat(
                    [run["metrics"]["peak_process_rss_bytes"] for run in query_runs]
                ),
                "peak_process_cpu_pct": normalize_stat(
                    [run["metrics"]["peak_process_cpu_pct"] for run in query_runs]
                ),
                "peak_thread_count": normalize_stat(
                    [run["metrics"]["peak_thread_count"] for run in query_runs]
                ),
                "peak_system_cpu_pct": normalize_stat(
                    [run["metrics"]["peak_system_cpu_pct"] for run in query_runs]
                ),
            }
        )
        run_index += 1

    benchmark_summary = {
        "measurement_runs": len(all_run_entries),
        "warmup_runs": warmup_runs * len(corpus),
        "duration_ms": normalize_stat([entry["metrics"]["duration_ms"] for entry in all_run_entries]),
        "kin_profile_total_ms": normalize_stat(
            [entry["metrics"]["kin_profile_total_ms"] for entry in all_run_entries]
        ),
        "peak_process_rss_bytes": normalize_stat(
            [entry["metrics"]["peak_process_rss_bytes"] for entry in all_run_entries]
        ),
        "peak_process_cpu_pct": normalize_stat(
            [entry["metrics"]["peak_process_cpu_pct"] for entry in all_run_entries]
        ),
        "peak_thread_count": normalize_stat(
            [entry["metrics"]["peak_thread_count"] for entry in all_run_entries]
        ),
        "peak_system_cpu_pct": normalize_stat(
            [entry["metrics"]["peak_system_cpu_pct"] for entry in all_run_entries]
        ),
        "queries": query_entries,
    }

    bench_manifest = {
        "format": "kin.performance_benchmark.v1",
        "mode": "benchmark",
        "command": command,
        "cwd": str(Path(cwd).resolve()),
        "corpus_path": str(Path(args.locate_corpus).resolve()),
        "repeats": measurement_runs,
        "warmups": warmup_runs,
        "started_at_unix": time.time(),
        "exit_code": exit_code,
        "runs": all_run_entries,
        "summary": {
            "benchmark": benchmark_summary,
        },
    }
    manifest_path = bundle_dir / "manifest.json"
    with manifest_path.open("w") as handle:
        json.dump(bench_manifest, handle, indent=2)

    runs_csv = bundle_dir / "runs.csv"
    with runs_csv.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "label",
                "query",
                "run_dir",
                "duration_ms",
                "kin_profile_total_ms",
                "peak_process_rss_bytes",
                "peak_process_cpu_pct",
                "peak_thread_count",
                "peak_system_cpu_pct",
                "exit_code",
            ]
        )
        for entry in all_run_entries:
            metrics = entry["metrics"]
            writer.writerow(
                [
                    entry["label"],
                    entry["query"],
                    entry["run_dir"],
                    metrics["duration_ms"],
                    metrics["kin_profile_total_ms"],
                    metrics["peak_process_rss_bytes"],
                    metrics["peak_process_cpu_pct"],
                    metrics["peak_thread_count"],
                    metrics["peak_system_cpu_pct"],
                    entry["exit_code"],
                ]
            )

    summary_path = bundle_dir / "summary.md"
    with summary_path.open("w") as handle:
        handle.write("# Kin Locate Benchmark\n\n")
        handle.write(f"- Corpus: `{bench_manifest['corpus_path']}`\n")
        handle.write(f"- Repeats: `{measurement_runs}`\n")
        handle.write(f"- Warmups: `{warmup_runs}`\n")
        handle.write(f"- Queries: `{len(corpus)}`\n")
        handle.write(
            f"- Measured runs: `{benchmark_summary['measurement_runs']}`\n"
        )
        handle.write(
            f"- Wall time median / p95: `{benchmark_summary['duration_ms']['median']}` ms / `{benchmark_summary['duration_ms']['p95']}` ms\n"
        )
        handle.write(
            f"- Kin span median / p95: `{benchmark_summary['kin_profile_total_ms']['median']}` ms / `{benchmark_summary['kin_profile_total_ms']['p95']}` ms\n"
        )
        handle.write(
            f"- Peak RSS median / p95: `{benchmark_summary['peak_process_rss_bytes']['median']}` / `{benchmark_summary['peak_process_rss_bytes']['p95']}` bytes\n"
        )
        handle.write(
            f"- Peak system CPU median / p95: `{benchmark_summary['peak_system_cpu_pct']['median']}`% / `{benchmark_summary['peak_system_cpu_pct']['p95']}`%\n"
        )
        handle.write("\n## Per-query summary\n\n")
        for query in query_entries:
            handle.write(
                f"- `{query['label']}`: wall median `{query['duration_ms']['median']}` ms, wall p95 `{query['duration_ms']['p95']}` ms, kin median `{query['kin_profile_total_ms']['median']}` ms, kin p95 `{query['kin_profile_total_ms']['p95']}` ms\n"
            )
        handle.write("\n## Artifacts\n\n")
        handle.write("- `runs/` one bundle per measured or warmup run\n")
        handle.write("- `runs.csv` machine-readable per-run metrics\n")
        handle.write("- `manifest.json` aggregate benchmark manifest\n")

    return RunResult(manifest=bench_manifest, bundle_dir=bundle_dir)


def main():
    parser = argparse.ArgumentParser(
        description="Profile a Kin command with Kin span timing plus sampled system/process telemetry."
    )
    parser.add_argument(
        "--bundle-dir",
        "--out",
        dest="bundle_dir",
        required=True,
        help="Directory to write the profiling bundle",
    )
    parser.add_argument("--cwd", default=os.getcwd(), help="Working directory for the profiled command")
    parser.add_argument("--resource-interval-ms", type=int, default=500)
    parser.add_argument("--sample-interval-ms", type=int, default=10)
    parser.add_argument("--sample-duration-sec", type=int, default=30)
    parser.add_argument("--no-sample", action="store_true", help="Skip macOS `sample` capture")
    parser.add_argument("--no-network", action="store_true", help="Skip per-process network sampling")
    parser.add_argument("--no-kin-profile", action="store_true", help="Do not inject `--profile-out` into the command")
    parser.add_argument(
        "--xctrace-template",
        action="append",
        default=[],
        help="Optional xctrace template, for example 'Time Profiler' or 'Metal System Trace'",
    )
    parser.add_argument(
        "--xctrace-time-limit",
        default="30s",
        help="Recording length for xctrace captures (default: 30s)",
    )
    parser.add_argument(
        "--locate-corpus",
        help="Run repeated locate profiling across a corpus file. Each non-empty line is QUERY or LABEL<TAB>QUERY.",
    )
    parser.add_argument(
        "--locate-repeats",
        type=int,
        default=5,
        help="Measured repeats per corpus query when --locate-corpus is set (default: 5)",
    )
    parser.add_argument(
        "--locate-warmups",
        type=int,
        default=1,
        help="Warmup runs per corpus query when --locate-corpus is set (default: 1)",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to profile. Use `-- <command ...>`")
    args = parser.parse_args()

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("missing command to profile")

    bundle_dir = Path(args.bundle_dir).resolve()
    bundle_dir.mkdir(parents=True, exist_ok=True)
    if args.locate_corpus:
        result = run_locate_corpus(command, args.cwd, bundle_dir, args)
    else:
        result = run_profile_bundle(command, args.cwd, bundle_dir, args, inject_profile_out=not args.no_kin_profile)

    if result.manifest.get("exit_code", 0) != 0:
        sys.exit(result.manifest["exit_code"])


if __name__ == "__main__":
    main()
