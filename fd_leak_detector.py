#!/usr/bin/env python3
"""
fd-leak-detector - Track down file descriptor leaks in running processes.

This utility monitors /proc to detect processes with growing FD counts,
helping identify potential file descriptor leaks in production systems.
"""

import os
import sys
import time
import argparse
from pathlib import Path
from collections import defaultdict
from datetime import datetime


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
    print(f"Starting FD leak monitoring (interval={interval}s, duration={duration}s)")
    print(f"Reporting processes with FD growth >= {threshold}\n")
    
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
            print(f"\n[{timestamp}] Potential leaks detected (iteration {iteration}):")
            print("-" * 70)
            for leak in leaks:
                print(f"  PID {leak['pid']:6} | {leak['name'][:40]:<40} | "
                      f"FDs: {leak['prev_fd']} -> {leak['curr_fd']} (+{leak['delta']})")
            print("-" * 70)
        else:
            print(f"[{timestamp}] No significant FD growth detected (iteration {iteration})")
        
        prev_snapshot = curr_snapshot
    
    print(f"\nMonitoring complete. {iteration} iterations performed.")


def inspect_process(pid, show_fds=False):
    """Inspect a specific process for FD usage."""
    info = get_process_info(pid)
    if not info:
        print(f"Cannot access process {pid} (may not exist or no permission)")
        return
    
    print(f"Process {pid}: {info['name']}")
    print(f"Current FD count: {info['fd_count']}")
    
    if show_fds:
        details = get_fd_details(pid)
        if details:
            print(f"\nFD breakdown by type:")
            for fd_type, count in sorted(details["by_type"].items()):
                print(f"  {fd_type}: {count}")
            
            print(f"\nOpen FDs (first {len(details['sample'])}):")
            for fd_num, target in details["sample"]:
                truncated = target if len(target) <= 60 else target[:57] + "..."
                print(f"  {fd_num:4} -> {truncated}")


def list_top_processes(top_n=20):
    """List processes sorted by FD count."""
    snapshot = snapshot_all_processes()
    sorted_procs = sorted(snapshot.values(), key=lambda x: x["fd_count"], reverse=True)
    
    print(f"Top {top_n} processes by FD count:\n")
    print(f"{'PID':>8} {'FD Count':>10}  Process")
    print("-" * 50)
    
    for proc in sorted_procs[:top_n]:
        name = proc["name"][:35] if len(proc["name"]) > 35 else proc["name"]
        print(f"{proc['pid']:8} {proc['fd_count']:10}  {name}")


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
    
    args = parser.parse_args()
    
    if not args.top and not args.monitor and not args.inspect and not args.high_fd:
        parser.print_help()
        sys.exit(0)
    
    if args.top:
        list_top_processes()
    
    if args.monitor:
        monitor_continuous(args.interval, args.duration, args.threshold)
    
    if args.inspect:
        inspect_process(args.inspect, args.show_fds)
    
    if args.high_fd:
        high_fd = find_high_fd_processes()
        if high_fd:
            print(f"Processes with high FD counts (>=100):\n")
            for proc in high_fd:
                print(f"  PID {proc['pid']:6} | FDs: {proc['fd_count']:5} | {proc['name']}")
        else:
            print("No processes found with FD count >= 100")


if __name__ == "__main__":
    main()
