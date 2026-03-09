# fd-leak-detector

Tiny utility to track down file descriptor leaks in running processes.

## Why I wrote this

Ever had a process slowly eat up all file descriptors until everything crashes? Yeah, me too. Usually happens at 3am on a Saturday. This tool helps catch those leaks before they become your problem.

It works by polling `/proc` to watch FD counts across all processes and flagging anything that's growing suspiciously fast.

## Quick start

```bash
python3 fd_leak_detector.py --top
```

That's it. You'll see which processes are hoarding FDs.

## Usage

### List top FD consumers

```bash
python3 fd_leak_detector.py --top
```

Shows the 20 processes with the most open file descriptors.

### Continuous monitoring

```bash
python3 fd_leak_detector.py --monitor --duration 60 --interval 2
```

Watches for FD growth over time. Reports any process whose FD count jumps by 10+ between snapshots.

Options:
- `--duration`: How long to monitor (default: 30s)
- `--interval`: Time between snapshots (default: 2s)
- `--threshold`: FD growth that triggers an alert (default: 10)

### Inspect a specific process

```bash
python3 fd_leak_detector.py --inspect 1234
python3 fd_leak_detector.py --inspect 1234 --show-fds
```

Get details about a single process. `--show-fds` lists the actual open descriptors (sockets, pipes, files, etc).

### Find high FD processes

```bash
python3 fd_leak_detector.py --high-fd
```

Lists all processes with 100+ open FDs. Good for quick sanity checks.

### Read FD leaks for a specific process

```bash
python3 fd_leak_detector.py --read-leaks 1234
python3 fd_leak_detector.py --read-leaks 1234 --samples 5 --interval 1
```

Takes multiple samples of a process's FDs and reports what's being leaked. Shows:
- Total FDs opened and closed between samples
- Net leak count
- Breakdown by FD type (socket, pipe, file, etc.)
- Sample of leaked FD targets

Options:
- `--samples`: Number of samples to take (default: 3)
- `--interval`: Time between samples in seconds (default: 2)

### Detailed monitoring mode

```bash
python3 fd_leak_detector.py --monitor-detailed --duration 60 --show-types
```

Like regular monitoring but shows what types of FDs are being leaked (sockets, pipes, files) with sample targets.

## What a leak looks like

Run the monitor and watch for output like:

```
[14:32:15] Potential leaks detected (iteration 3):
----------------------------------------------------------------------
  PID  45231 | python3 app.py                           | FDs: 150 -> 203 (+53)
  PID  12094 | node server.js                           | FDs: 89 -> 112 (+23)
----------------------------------------------------------------------
```

That python process gaining 53 FDs in 4 seconds? Yeah, that's your leak.

## How it works

1. Reads `/proc/<pid>/fd` to count open file descriptors
2. Takes snapshots at regular intervals
3. Compares snapshots to find growing FD counts
4. Classifies FDs by type (socket, pipe, file, etc.)

No kernel modules, no ptrace, no fancy stuff. Just reading procfs like a normal person.

## Limitations

- Linux only (uses /proc)
- Need read access to /proc/<pid>/fd (usually fine for your own processes)
- Can't see inside containers without extra setup
- Won't tell you *why* the FDs aren't being closed, just that they're not

## When to use this

- Debugging "too many open files" errors
- Checking if that new library actually closes its connections
- Pre-deployment sanity check on long-running services
- That 3am Saturday incident I mentioned

## License

Do whatever you want with it.
