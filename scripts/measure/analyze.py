"""Join a 2 Hz RSS trace to the daemon's own authority-open windows.

The question this answers is the one that decides which repo the fix is in:
is the resident set N simultaneous decoded copies of the authority, or one
copy that is N times the file? Time per open is already measured elsewhere.
Bytes per open is not, and it is what separates the two.

Every parse strips ANSI first, because the daemon writes colour codes between
a field name and its value, and a byte-level grep for `field=value` therefore
never matches while lifecycle lines false-positive (docs/traps.md).
"""
import re
import sys
import os
import datetime

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def strip(line):
    return ANSI.sub("", line)


def parse_ts(text):
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)", text)
    if not m:
        return None
    return datetime.datetime.strptime(
        m.group(1)[:26] + "Z", "%Y-%m-%dT%H:%M:%S.%fZ"
    ).replace(tzinfo=datetime.timezone.utc).timestamp() * 1000.0


def main(out):
    log = os.path.join(out, "daemon.log")
    if not os.path.exists(log):
        raise SystemExit("REFUSING: no daemon.log in %s" % out)
    raw = open(log, "rb").read().decode("utf-8", "replace")
    text = strip(raw)

    # Controls on the needles, so an absence is an absence and not a typo.
    control_present = text.count("daemon startup phases completed")
    control_absent = text.count("zzz-fabricated-needle-daemonres")
    print("needle control: 'daemon startup phases completed' = %d (must be >0)" % control_present)
    print("needle control: fabricated                        = %d (must be 0)" % control_absent)
    if control_present == 0 or control_absent != 0:
        raise SystemExit("REFUSING: needle controls failed, the parse is not trustworthy")

    for line in text.splitlines():
        if "daemon startup phases completed" in line:
            print("STARTUP " + line.split("daemon startup phases completed", 1)[1].strip())

    opens = []
    for line in text.splitlines():
        if "repository authority open" not in line:
            continue
        ts = parse_ts(line)
        m = re.search(r"total_ms=(\d+)", line)
        if ts is None or not m:
            continue
        total = int(m.group(1))
        fields = dict(re.findall(r"(\w+)=(\w+)", line))
        opens.append(
            {
                "end": ts,
                "start": ts - total,
                "total_ms": total,
                "bodies_ms": int(fields.get("bodies_ms", 0)),
                "recover_ms": int(fields.get("recover_ms", 0)),
                "replay_ms": int(fields.get("replay_ms", 0)),
            }
        )
    opens.sort(key=lambda o: o["start"])
    print()
    print("authority opens in this arm: %d" % len(opens))
    if opens:
        print("  total open work   %.1f s" % (sum(o["total_ms"] for o in opens) / 1000.0))
        print("  bodies_ms summed  %.1f s" % (sum(o["bodies_ms"] for o in opens) / 1000.0))
        print("  recover_ms summed %.1f s" % (sum(o["recover_ms"] for o in opens) / 1000.0))
        print("  replay_ms summed  %.1f s" % (sum(o["replay_ms"] for o in opens) / 1000.0))
        print("  min/max total_ms  %d / %d" % (min(o["total_ms"] for o in opens), max(o["total_ms"] for o in opens)))

    # Concurrency over time, from each open's own derived window.
    events = []
    for o in opens:
        events.append((o["start"], 1))
        events.append((o["end"], -1))
    events.sort()
    live = 0
    peak_conc = 0
    peak_at = None
    timeline = []
    for t, delta in events:
        live += delta
        timeline.append((t, live))
        if live > peak_conc:
            peak_conc, peak_at = live, t
    print("  peak concurrent   %d" % peak_conc)

    rss_path = os.path.join(out, "rss.txt")
    rows = []
    for line in open(rss_path):
        parts = line.split()
        if len(parts) != 4:
            continue
        rows.append((int(parts[0]), parts[1], int(parts[2]), int(parts[3])))
    if not rows:
        raise SystemExit("REFUSING: no RSS samples")
    daemon_rows = [r for r in rows if r[1] == "kin-daemon"]
    if not daemon_rows:
        raise SystemExit("REFUSING: no kin-daemon RSS samples")

    phases = {}
    for line in open(os.path.join(out, "phases.txt")):
        p = line.split()
        if len(p) >= 4 and p[0] == "PHASE":
            phases.setdefault(p[1], {})[p[2]] = (int(p[3]), p[4] if len(p) > 4 else "")

    t0 = rows[0][0]

    def gib(kb):
        return kb / 1048576.0

    def window_peak(lo, hi):
        vals = [r[3] for r in daemon_rows if lo <= r[0] <= hi]
        return (max(vals), min(vals)) if vals else (0, 0)

    print()
    print("%-34s %10s %10s   %s" % ("phase", "peak GiB", "floor GiB", "rc"))
    for name in ("daemon_start", "settle", "status1", "status2", "idle", "stop"):
        if name not in phases or "start" not in phases[name]:
            print("%-34s %10s" % (name, "NOT RUN"))
            continue
        lo = phases[name]["start"][0]
        hi = phases[name]["end"][0] if "end" in phases[name] else rows[-1][0]
        pk, fl = window_peak(lo, hi)
        rc = phases[name]["end"][1] if "end" in phases[name] else "rc=?"
        print("%-34s %10.3f %10.3f   %s" % (name, gib(pk), gib(fl), rc))

    whole_peak = max(r[3] for r in daemon_rows)
    print()
    print("daemon peak RSS over the arm      %.3f GiB" % gib(whole_peak))

    # The join: daemon RSS against the number of authority opens in flight.
    if opens:
        print()
        print("%-14s %12s %12s %8s" % ("concurrency", "samples", "mean GiB", "max GiB"))
        buckets = {}
        for t, comm, pid, rss in daemon_rows:
            live = 0
            for ot, d in timeline:
                if ot <= t:
                    live += d
                else:
                    break
            buckets.setdefault(live, []).append(rss)
        for k in sorted(buckets):
            v = buckets[k]
            print("%-14d %12d %12.3f %8.3f" % (k, len(v), gib(sum(v) / len(v)), gib(max(v))))
        base = buckets.get(0)
        if base and peak_conc > 0:
            floor_at_zero = sum(base) / len(base)
            top = max(max(v) for v in buckets.values())
            print()
            print("mean daemon RSS with zero opens in flight   %.3f GiB" % gib(floor_at_zero))
            print("max  daemon RSS at any concurrency          %.3f GiB" % gib(top))
            print("derived GiB per concurrent open            %.3f  (label: DERIVED, (max-floor)/peak_concurrency)"
                  % (gib(top - floor_at_zero) / peak_conc))


if __name__ == "__main__":
    main(sys.argv[1])
