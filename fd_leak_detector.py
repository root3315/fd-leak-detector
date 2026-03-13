#!/usr/bin/env python3
"""
fd-leak-detector - Track down file descriptor leaks in running processes.

This utility monitors /proc to detect processes with growing FD counts,
helping identify potential file descriptor leaks in production systems.
"""

import json
import logging
import os
import sys
import time
import argparse
from pathlib import Path
from collections import defaultdict
from datetime import datetime


logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
)
logger = logging.getLogger(__name__)

PROC_PATH = Path("/proc")


def get_process_info(pid):
    """Extract process name and FD count for a given PID."""
    try:
        proc_dir = PROC_PATH / str(pid)
        if not proc_dir.exists():
            return None

        cmdline_path = proc_dir / "cmdline"
        fd_dir = proc_dir / "fd"

        try:
            with open(cmdline_path, "r") as f:
                cmdline = f.read().replace("\x00", " ").strip()
        except (PermissionError, FileNotFoundError):
            cmdline = "<unknown>"

        if not cmdline:
            try:
                with open(proc_dir / "comm", "r") as f:
                    cmdline = f.read().strip()
            except (PermissionError, FileNotFoundError):
                cmdline = "<unknown>"

        try:
            fd_count = len(list(fd_dir.iterdir()))
        except (PermissionError, FileNotFoundError):
            return None

        return {
            "pid": pid,
            "name": cmdline,
            "fd_count": fd_count
        }
    except Exception:
        return None


def get_fd_details(pid, limit=50):
    """Get details about open file descriptors for a process."""
    try:
        fd_dir = PROC_PATH / str(pid) / "fd"
        fds = []

        for fd_path in fd_dir.iterdir():
            try:
                target = os.readlink(fd_path)
                fd_num = int(fd_path.name)
                fds.append((fd_num, target))
            except (OSError, ValueError):
                continue

        fds.sort(key=lambda x: x[0])

        fd_types = defaultdict(int)
        for _, target in fds:
            if target.startswith("socket:"):
                fd_types["socket"] += 1
            elif target.startswith("pipe:"):
                fd_types["pipe"] += 1
            elif target.startswith("/dev/"):
                fd_types["device"] += 1
            elif target.startswith("anon_inode:"):
                fd_types["anon_inode"] += 1
            elif target == "/dev/null":
                fd_types["null"] += 1
            elif target.startswith("/"):
                fd_types["file"] += 1
            else:
                fd_types["other"] += 1

        return {
            "total": len(fds),
            "by_type": dict(fd_types),
            "sample": fds[:limit]
        }
    except (PermissionError, FileNotFoundError):
        return None


def snapshot_fd_targets(pid):
    """Capture a set of FD targets for a process (for leak comparison)."""
    try:
        fd_dir = PROC_PATH / str(pid) / "fd"
        targets = set()

        for fd_path in fd_dir.iterdir():
            try:
                target = os.readlink(fd_path)
                targets.add(target)
            except (OSError, ValueError):
                continue

        return targets
    except (PermissionError, FileNotFoundError):
        return None


def analyze_leak_details(pid, prev_targets, curr_targets):
    """Analyze what specific FDs were leaked between snapshots."""
    new_fds = curr_targets - prev_targets
    removed_fds = prev_targets - curr_targets

    leak_types = defaultdict(list)
    for target in new_fds:
        if target.startswith("socket:"):
            leak_types["socket"].append(target)
        elif target.startswith("pipe:"):
            leak_types["pipe"].append(target)
        elif target.startswith("/dev/"):
            leak_types["device"].append(target)
        elif target.startswith("anon_inode:"):
            leak_types["anon_inode"].append(target)
        elif target.startswith("/"):
            leak_types["file"].append(target)
        else:
            leak_types["other"].append(target)

    return {
        "new_fds": list(new_fds),
        "removed_fds": list(removed_fds),
        "leak_types": dict(leak_types),
        "net_leak": len(new_fds) - len(removed_fds)
    }


def snapshot_all_processes():
    """Take a snapshot of FD counts for all accessible processes."""
    snapshot = {}

    for entry in PROC_PATH.iterdir():
        if not entry.name.isdigit():
            continue

        pid = int(entry.name)
        info = get_process_info(pid)
        if info:
            snapshot[pid] = info

    return snapshot


def snapshot_all_processes_detailed():
    """Take a detailed snapshot including FD targets for leak analysis."""
    snapshot = {}

    for entry in PROC_PATH.iterdir():
        if not entry.name.isdigit():
            continue

        pid = int(entry.name)
        info = get_process_info(pid)
        if info:
            targets = snapshot_fd_targets(pid)
            snapshot[pid] = {
                **info,
                "fd_targets": targets
            }

    return snapshot


def detect_leaks(prev_snapshot, curr_snapshot, threshold=10):
    """
    Detect potential FD leaks by comparing two snapshots.

    A leak is suspected when FD count grows significantly between snapshots.
    """
    leaks = []

    for pid, curr_info in curr_snapshot.items():
        if pid not in prev_snapshot:
            continue

        prev_info = prev_snapshot[pid]
        fd_delta = curr_info["fd_count"] - prev_info["fd_count"]

        if fd_delta >= threshold:
            leaks.append({
                "pid": pid,
                "name": curr_info["name"],
                "prev_fd": prev_info["fd_count"],
                "curr_fd": curr_info["fd_count"],
                "delta": fd_delta
            })

    leaks.sort(key=lambda x: x["delta"], reverse=True)
    return leaks


def detect_leaks_detailed(prev_snapshot, curr_snapshot, threshold=10):
    """
    Detect FD leaks with detailed information about what was leaked.

    Returns leak information including the specific FD targets that are new.
    """
    leaks = []

    for pid, curr_info in curr_snapshot.items():
        if pid not in prev_snapshot:
            continue

        prev_info = prev_snapshot[pid]
        fd_delta = curr_info["fd_count"] - prev_info["fd_count"]

        if fd_delta >= threshold:
            prev_targets = prev_info.get("fd_targets", set())
            curr_targets = curr_info.get("fd_targets", set())

            if prev_targets and curr_targets:
                analysis = analyze_leak_details(pid, prev_targets, curr_targets)
            else:
                analysis = None

            leaks.append({
                "pid": pid,
                "name": curr_info["name"],
                "prev_fd": prev_info["fd_count"],
                "curr_fd": curr_info["fd_count"],
                "delta": fd_delta,
                "details": analysis
            })

    leaks.sort(key=lambda x: x["delta"], reverse=True)
    return leaks


def find_high_fd_processes(min_fd_count=100):
    """Find processes with unusually high FD counts."""
    high_fd = []

    for entry in PROC_PATH.iterdir():
        if not entry.name.isdigit():
            continue

        pid = int(entry.name)
        info = get_process_info(pid)
        if info and info["fd_count"] >= min_fd_count:
            high_fd.append(info)

    high_fd.sort(key=lambda x: x["fd_count"], reverse=True)
    return high_fd


def monitor_continuous(interval=2, duration=30, threshold=10):
    """
    Continuously monitor FD counts and report potential leaks.

    Takes snapshots at regular intervals and compares them to detect
    processes with growing FD counts.
    """
    logger.info(f"Starting FD leak monitoring (interval={interval}s, duration={duration}s)")
    logger.info(f"Reporting processes with FD growth >= {threshold}\n")

    start_time = time.time()
    prev_snapshot = snapshot_all_processes()

    iteration = 0
    while time.time() - start_time < duration:
        time.sleep(interval)
        iteration += 1

        curr_snapshot = snapshot_all_processes()
        leaks = detect_leaks(prev_snapshot, curr_snapshot, threshold)

        timestamp = datetime.now().strftime("%H:%M:%S")

        if leaks:
            logger.info(f"\n[{timestamp}] Potential leaks detected (iteration {iteration}):")
            logger.info("-" * 70)
            for leak in leaks:
                logger.info(f"  PID {leak['pid']:6} | {leak['name'][:40]:<40} | "
                            f"FDs: {leak['prev_fd']} -> {leak['curr_fd']} (+{leak['delta']})")
            logger.info("-" * 70)
        else:
            logger.info(f"[{timestamp}] No significant FD growth detected (iteration {iteration})")

        prev_snapshot = curr_snapshot

    logger.info(f"\nMonitoring complete. {iteration} iterations performed.")


def monitor_leaks_detailed(interval=2, duration=30, threshold=10, show_types=False):
    """
    Monitor FD leaks with detailed information about what's being leaked.

    Tracks specific FD targets to identify what types of descriptors are leaking.
    """
    logger.info(f"Starting detailed FD leak monitoring (interval={interval}s, duration={duration}s)")
    logger.info(f"Reporting processes with FD growth >= {threshold}\n")

    start_time = time.time()
    prev_snapshot = snapshot_all_processes_detailed()

    iteration = 0
    while time.time() - start_time < duration:
        time.sleep(interval)
        iteration += 1

        curr_snapshot = snapshot_all_processes_detailed()
        leaks = detect_leaks_detailed(prev_snapshot, curr_snapshot, threshold)

        timestamp = datetime.now().strftime("%H:%M:%S")

        if leaks:
            logger.info(f"\n[{timestamp}] Potential leaks detected (iteration {iteration}):")
            logger.info("=" * 70)
            for leak in leaks:
                logger.info(f"  PID {leak['pid']:6} | {leak['name'][:35]:<35} | "
                            f"FDs: {leak['prev_fd']} -> {leak['curr_fd']} (+{leak['delta']})")

                if leak["details"]:
                    details = leak["details"]
                    if show_types and details["leak_types"]:
                        logger.info(f"    Leaked by type:")
                        for fd_type, targets in sorted(details["leak_types"].items()):
                            sample = targets[:3]
                            suffix = "..." if len(targets) > 3 else ""
                            logger.info(f"      {fd_type}: +{len(targets)} {suffix}")
                            for t in sample:
                                truncated = t[:55] + "..." if len(t) > 55 else t
                                logger.info(f"        -> {truncated}")
            logger.info("=" * 70)
        else:
            logger.info(f"[{timestamp}] No significant FD growth detected (iteration {iteration})")

        prev_snapshot = curr_snapshot

    logger.info(f"\nMonitoring complete. {iteration} iterations performed.")


def inspect_process(pid, show_fds=False):
    """Inspect a specific process for FD usage."""
    info = get_process_info(pid)
    if not info:
        logger.warning(f"Cannot access process {pid} (may not exist or no permission)")
        return

    logger.info(f"Process {pid}: {info['name']}")
    logger.info(f"Current FD count: {info['fd_count']}")

    if show_fds:
        details = get_fd_details(pid)
        if details:
            logger.info(f"\nFD breakdown by type:")
            for fd_type, count in sorted(details["by_type"].items()):
                logger.info(f"  {fd_type}: {count}")

            logger.info(f"\nOpen FDs (first {len(details['sample'])}):")
            for fd_num, target in details["sample"]:
                truncated = target if len(target) <= 60 else target[:57] + "..."
                logger.info(f"  {fd_num:4} -> {truncated}")


def read_process_leaks(pid, interval=2, samples=3):
    """
    Read FD leaks for a specific process by taking multiple samples.

    Compares FD targets between samples to identify what's being leaked.
    """
    logger.info(f"Reading FD leaks for process {pid}...")
    logger.info(f"Taking {samples} samples at {interval}s intervals\n")

    info = get_process_info(pid)
    if not info:
        logger.warning(f"Cannot access process {pid}")
        return

    logger.info(f"Process: {info['name']}")
    logger.info(f"Initial FD count: {info['fd_count']}\n")

    prev_targets = snapshot_fd_targets(pid)
    if prev_targets is None:
        logger.warning(f"Cannot read FDs for process {pid} (permission denied or process ended)")
        return

    total_new = set()
    total_removed = set()

    for i in range(samples - 1):
        time.sleep(interval)

        curr_targets = snapshot_fd_targets(pid)
        if curr_targets is None:
            logger.warning(f"Process {pid} ended during monitoring")
            break

        new_fds = curr_targets - prev_targets
        removed_fds = prev_targets - curr_targets

        total_new.update(new_fds)
        total_removed.update(removed_fds)

        if new_fds or removed_fds:
            logger.info(f"  Sample {i + 2}: +{len(new_fds)} new, -{len(removed_fds)} closed")

        prev_targets = curr_targets

    net_leak = len(total_new) - len(total_removed)

    logger.info(f"\n--- Leak Summary for PID {pid} ---")
    logger.info(f"Total new FDs opened:   {len(total_new)}")
    logger.info(f"Total FDs closed:       {len(total_removed)}")
    logger.info(f"Net FD leak:            {net_leak}")

    if total_new:
        leak_types = defaultdict(list)
        for target in total_new:
            if target.startswith("socket:"):
                leak_types["socket"].append(target)
            elif target.startswith("pipe:"):
                leak_types["pipe"].append(target)
            elif target.startswith("/dev/"):
                leak_types["device"].append(target)
            elif target.startswith("anon_inode:"):
                leak_types["anon_inode"].append(target)
            elif target.startswith("/"):
                leak_types["file"].append(target)
            else:
                leak_types["other"].append(target)

        logger.info(f"\nLeaked FDs by type:")
        for fd_type, targets in sorted(leak_types.items()):
            logger.info(f"  {fd_type}: {len(targets)}")
            for t in targets[:5]:
                truncated = t[:55] + "..." if len(t) > 55 else t
                logger.info(f"    -> {truncated}")
            if len(targets) > 5:
                logger.info(f"    ... and {len(targets) - 5} more")

    if net_leak > 0:
        logger.warning(f"Process has a net leak of {net_leak} FDs")
    elif net_leak < 0:
        logger.info(f"Process closed {abs(net_leak)} more FDs than it opened")
    else:
        logger.info(f"No net FD leak detected")


def list_top_processes(top_n=20):
    """List processes sorted by FD count."""
    snapshot = snapshot_all_processes()
    sorted_procs = sorted(snapshot.values(), key=lambda x: x["fd_count"], reverse=True)

    logger.info(f"Top {top_n} processes by FD count:\n")
    logger.info(f"{'PID':>8} {'FD Count':>10}  Process")
    logger.info("-" * 50)

    for proc in sorted_procs[:top_n]:
        name = proc["name"][:35] if len(proc["name"]) > 35 else proc["name"]
        logger.info(f"{proc['pid']:8} {proc['fd_count']:10}  {name}")


def list_top_processes_json(top_n=20):
    """List processes sorted by FD count in JSON format."""
    snapshot = snapshot_all_processes()
    sorted_procs = sorted(snapshot.values(), key=lambda x: x["fd_count"], reverse=True)

    result = {
        "timestamp": datetime.now().isoformat(),
        "top_n": top_n,
        "processes": [
            {"pid": p["pid"], "fd_count": p["fd_count"], "name": p["name"]}
            for p in sorted_procs[:top_n]
        ]
    }
    print(json.dumps(result, indent=2))


def inspect_process_json(pid, show_fds=False):
    """Inspect a specific process for FD usage in JSON format."""
    info = get_process_info(pid)
    if not info:
        result = {
            "error": f"Cannot access process {pid}",
            "pid": pid
        }
        print(json.dumps(result, indent=2))
        return

    result = {
        "pid": pid,
        "name": info["name"],
        "fd_count": info["fd_count"]
    }

    if show_fds:
        details = get_fd_details(pid)
        if details:
            result["fd_breakdown"] = details["by_type"]
            result["open_fds"] = [
                {"fd": fd_num, "target": target}
                for fd_num, target in details["sample"]
            ]

    print(json.dumps(result, indent=2))


def find_high_fd_processes_json(min_fd_count=100):
    """Find processes with high FD counts in JSON format."""
    high_fd = find_high_fd_processes(min_fd_count)

    result = {
        "timestamp": datetime.now().isoformat(),
        "min_fd_count": min_fd_count,
        "count": len(high_fd),
        "processes": [
            {"pid": p["pid"], "fd_count": p["fd_count"], "name": p["name"]}
            for p in high_fd
        ]
    }
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Track down file descriptor leaks in running processes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --top              List top processes by FD count
  %(prog)s --monitor          Continuous monitoring mode
  %(prog)s --inspect 1234     Inspect specific process
  %(prog)s --high-fd          Find processes with high FD counts
  %(prog)s --read-leaks 1234  Read FD leaks for a specific process
  %(prog)s --monitor-detailed Detailed leak monitoring with FD types
  %(prog)s --top --json       Output as JSON for programmatic use
        """
    )

    parser.add_argument("--top", "-t", action="store_true",
                        help="List top processes by FD count")
    parser.add_argument("--monitor", "-m", action="store_true",
                        help="Continuous monitoring mode")
    parser.add_argument("--inspect", "-i", type=int, metavar="PID",
                        help="Inspect a specific process by PID")
    parser.add_argument("--high-fd", "-H", action="store_true",
                        help="Find processes with high FD counts (>=100)")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="Monitoring interval in seconds (default: 2)")
    parser.add_argument("--duration", type=float, default=30.0,
                        help="Monitoring duration in seconds (default: 30)")
    parser.add_argument("--threshold", type=int, default=10,
                        help="FD growth threshold for leak detection (default: 10)")
    parser.add_argument("--show-fds", action="store_true",
                        help="Show individual FDs when inspecting")
    parser.add_argument("--read-leaks", "-r", type=int, metavar="PID",
                        help="Read FD leaks for a specific process")
    parser.add_argument("--samples", type=int, default=3,
                        help="Number of samples for leak reading (default: 3)")
    parser.add_argument("--monitor-detailed", action="store_true",
                        help="Detailed monitoring showing leaked FD types")
    parser.add_argument("--show-types", action="store_true",
                        help="Show FD types in detailed monitoring")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output results as JSON")

    args = parser.parse_args()

    if not any([args.top, args.monitor, args.inspect, args.high_fd,
                args.read_leaks, args.monitor_detailed]):
        parser.print_help()
        sys.exit(0)

    if args.top:
        if args.json:
            list_top_processes_json()
        else:
            list_top_processes()

    if args.monitor:
        monitor_continuous(args.interval, args.duration, args.threshold)

    if args.inspect:
        if args.json:
            inspect_process_json(args.inspect, args.show_fds)
        else:
            inspect_process(args.inspect, args.show_fds)

    if args.high_fd:
        if args.json:
            find_high_fd_processes_json()
        else:
            high_fd = find_high_fd_processes()
            if high_fd:
                logger.info(f"Processes with high FD counts (>=100):\n")
                for proc in high_fd:
                    logger.info(f"  PID {proc['pid']:6} | FDs: {proc['fd_count']:5} | {proc['name']}")
            else:
                logger.info("No processes found with FD count >= 100")

    if args.read_leaks:
        read_process_leaks(args.read_leaks, args.interval, args.samples)

    if args.monitor_detailed:
        monitor_leaks_detailed(args.interval, args.duration, args.threshold, args.show_types)


if __name__ == "__main__":
    main()
