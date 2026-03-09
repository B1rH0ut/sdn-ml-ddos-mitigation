#!/usr/bin/env python3
"""
Normal Traffic Generator for SDN DDoS Detection Testing

Generates realistic normal network traffic within a Mininet environment
to simulate legitimate user activity. This traffic is used for:
1. Training the ML model (collecting normal flow statistics)
2. Testing the controller's ability to distinguish normal from attack traffic
3. Validating network connectivity and performance

Traffic Distribution:
    - ICMP (ping):  30% - Simulates connectivity checks
    - TCP (iperf):  50% - Simulates file transfers and data streams
    - HTTP (wget):  20% - Simulates web browsing (h1 as server)

Usage:
    Run from within Mininet CLI or as a Mininet script:

    From Mininet CLI:
        mininet> h1 python3 /path/to/generate_normal.py --duration 300

    As standalone (must be run inside Mininet environment):
        sudo python3 generate_normal.py --duration 300 --verbose

Requirements:
    - Must be run inside a Mininet environment
    - Hosts h1-h10 must exist with IPs 10.0.0.1-10
    - iperf must be installed on Mininet hosts
    - Root privileges required (Mininet requirement)

"""

import os
import time
import random
import argparse
import subprocess
import signal
import sys
import atexit


# Host configuration matching network_topology/topology.py
HOSTS = [f'h{i}' for i in range(1, 11)]            # h1-h10
HOST_IPS = [f'10.0.0.{i}' for i in range(1, 11)]   # 10.0.0.1-10

# Track PIDs of background processes for reliable cleanup
_background_pids = []

# Single HTTP server instance to prevent process leak
_http_server_proc = None

# Web server host (used for HTTP traffic)
WEB_SERVER_HOST = 'h1'
WEB_SERVER_IP = '10.0.0.1'
WEB_SERVER_PORT = 8080

# Traffic type weights (must sum to 1.0)
TRAFFIC_WEIGHTS = {
    'icmp': 0.30,   # 30% ping traffic
    'tcp':  0.50,   # 50% iperf traffic
    'http': 0.20    # 20% wget traffic
}


class TrafficStats:
    """
    Track statistics for generated traffic.

    Attributes:
        icmp_count (int): Number of ICMP (ping) sessions generated.
        tcp_count (int): Number of TCP (iperf) sessions generated.
        http_count (int): Number of HTTP (wget) requests generated.
        errors (int): Number of failed traffic generation attempts.
        start_time (float): Timestamp when generation started.
    """

    def __init__(self):
        """Initialize all counters to zero."""
        self.icmp_count = 0
        self.tcp_count = 0
        self.http_count = 0
        self.errors = 0
        self.start_time = time.time()

    @property
    def total(self):
        """Return total number of successful traffic sessions."""
        return self.icmp_count + self.tcp_count + self.http_count

    @property
    def elapsed(self):
        """Return elapsed time in seconds since generation started."""
        return time.time() - self.start_time

    def summary(self):
        """Print a formatted summary of all traffic statistics."""
        print("\n" + "=" * 60)
        print("  Normal Traffic Generation - Summary")
        print("=" * 60)
        print(f"  Duration:        {self.elapsed:.1f} seconds")
        print(f"  Total sessions:  {self.total}")
        print(f"  ICMP (ping):     {self.icmp_count} "
              f"({self.icmp_count / max(self.total, 1) * 100:.1f}%)")
        print(f"  TCP (iperf):     {self.tcp_count} "
              f"({self.tcp_count / max(self.total, 1) * 100:.1f}%)")
        print(f"  HTTP (wget):     {self.http_count} "
              f"({self.http_count / max(self.total, 1) * 100:.1f}%)")
        print(f"  Errors:          {self.errors}")
        print("=" * 60 + "\n")


def get_random_host_pair():
    """
    Select two different random hosts for traffic generation.

    Returns:
        tuple: (source_ip, dest_ip) as string IP addresses.
    """
    src_idx, dst_idx = random.sample(range(len(HOST_IPS)), 2)
    return HOST_IPS[src_idx], HOST_IPS[dst_idx]


def run_command(cmd, verbose=False):
    """
    Execute a command and return success status.

    Args:
        cmd (list): Command as a list of arguments (no shell=True).
        verbose (bool): If True, print the command before executing.

    Returns:
        bool: True if command succeeded (exit code 0), False otherwise.
    """
    if verbose:
        print(f"    CMD: {cmd}")

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120  # 2-minute timeout to prevent hanging
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except (subprocess.SubprocessError, OSError):
        return False


def start_background(cmd, verbose=False):
    """
    Start a command as a background process and track its PID.

    Args:
        cmd (list): Command as a list of arguments (no shell=True).
        verbose (bool): If True, print the command being executed.

    Returns:
        subprocess.Popen or None: The process object, or None on failure.
    """
    if verbose:
        print(f"    BG CMD: {cmd}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        _background_pids.append(proc.pid)
        return proc
    except (subprocess.SubprocessError, OSError):
        return None


def generate_icmp_traffic(verbose=False):
    """
    Generate ICMP ping traffic between random host pairs.

    Simulates connectivity checks by sending 5-20 ICMP echo requests
    between two randomly selected hosts.

    Args:
        verbose (bool): If True, print detailed command information.

    Returns:
        bool: True if ping command succeeded, False otherwise.
    """
    src_ip, dst_ip = get_random_host_pair()
    ping_count = random.randint(5, 20)

    if verbose:
        print(f"  [ICMP] {src_ip} -> {dst_ip} ({ping_count} pings)")

    cmd = ["ping", "-c", str(ping_count), "-W", "1", dst_ip]
    return run_command(cmd, verbose)


def generate_tcp_traffic(verbose=False):
    """
    Generate TCP traffic using iperf between random host pairs.

    Simulates file transfers and data streams by running iperf in client
    mode for a random duration between 10-60 seconds.

    Note: Requires an iperf server running on the destination host.
    In Mininet, iperf can be started on hosts directly.

    Args:
        verbose (bool): If True, print detailed command information.

    Returns:
        bool: True if iperf command succeeded, False otherwise.
    """
    src_ip, dst_ip = get_random_host_pair()
    duration = random.randint(10, 60)

    if verbose:
        print(f"  [TCP]  {src_ip} -> {dst_ip} (iperf, {duration}s)")

    # Start iperf server on destination (background, tracked for cleanup)
    server_proc = start_background(["iperf", "-s", "-p", "5001"], verbose=False)

    # Small delay to let server start
    time.sleep(0.5)

    # Run iperf client
    client_cmd = ["iperf", "-c", dst_ip, "-p", "5001", "-t", str(duration)]
    success = run_command(client_cmd, verbose)

    # Kill the specific iperf server we started
    if server_proc is not None:
        try:
            server_proc.terminate()
            server_proc.wait(timeout=5)
        except (subprocess.SubprocessError, OSError):
            try:
                server_proc.kill()
            except (subprocess.SubprocessError, OSError):
                pass

    return success


def _ensure_http_server(verbose=False):
    """
    Start the HTTP server once and reuse it to prevent process leak.

    Only starts a new server if one isn't already running. Registers
    cleanup via atexit to ensure the server is terminated on exit.
    """
    global _http_server_proc

    # Already running and alive
    if _http_server_proc is not None and _http_server_proc.poll() is None:
        return

    server_cmd = [
        "python3", "-m", "http.server",
        str(WEB_SERVER_PORT), "--directory", "/tmp"
    ]
    _http_server_proc = start_background(server_cmd, verbose=verbose)

    # Brief startup delay only on first launch
    if _http_server_proc is not None:
        time.sleep(0.5)


def _cleanup_http_server():
    """Terminate the HTTP server process if running."""
    global _http_server_proc
    if _http_server_proc is not None:
        try:
            _http_server_proc.terminate()
            _http_server_proc.wait(timeout=5)
        except (subprocess.SubprocessError, OSError):
            try:
                _http_server_proc.kill()
            except (subprocess.SubprocessError, OSError):
                pass
        _http_server_proc = None


# Register HTTP server cleanup at interpreter exit
atexit.register(_cleanup_http_server)


def generate_http_traffic(verbose=False):
    """
    Generate HTTP traffic by making wget requests to h1 (web server).

    Simulates web browsing by downloading small files from h1 acting as
    an HTTP server. A single Python HTTP server is started on h1 and
    reused across calls.

    Args:
        verbose (bool): If True, print detailed command information.

    Returns:
        bool: True if wget command succeeded, False otherwise.
    """
    # Select a random client (h2-h10, not h1 since h1 is the server)
    client_ip = random.choice(HOST_IPS[1:])  # Skip 10.0.0.1 (h1/server)

    if verbose:
        print(f"  [HTTP] {client_ip} -> {WEB_SERVER_IP}:{WEB_SERVER_PORT}")

    # Start HTTP server once, reuse across calls
    _ensure_http_server(verbose=False)

    # Download from the server using wget
    wget_cmd = [
        "wget", "-q", "-O", "/dev/null",
        "--timeout=10", "--tries=1",
        f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/"
    ]
    return run_command(wget_cmd, verbose)


def select_traffic_type():
    """
    Randomly select a traffic type based on configured weights.

    Uses weighted random selection:
    - 30% chance: ICMP (ping)
    - 50% chance: TCP (iperf)
    - 20% chance: HTTP (wget)

    Returns:
        str: Traffic type ('icmp', 'tcp', or 'http').
    """
    rand = random.random()
    cumulative = 0.0

    for traffic_type, weight in TRAFFIC_WEIGHTS.items():
        cumulative += weight
        if rand <= cumulative:
            return traffic_type

    # Fallback (should not reach here due to floating point)
    return 'icmp'


def generate_traffic(duration, verbose=False):
    """
    Main traffic generation loop.

    Generates mixed normal traffic for the specified duration, randomly
    selecting between ICMP, TCP, and HTTP traffic types according to
    the configured weights. Prints progress updates every 30 seconds.

    Args:
        duration (int): Total duration in seconds to generate traffic.
        verbose (bool): If True, print detailed information for each
                        traffic session.
    """
    stats = TrafficStats()
    last_progress = 0
    progress_interval = 30  # Print progress every 30 seconds

    # Traffic generator function mapping
    generators = {
        'icmp': generate_icmp_traffic,
        'tcp':  generate_tcp_traffic,
        'http': generate_http_traffic
    }

    print("\n" + "=" * 60)
    print("  Normal Traffic Generation Started")
    print("=" * 60)
    print(f"  Duration:    {duration} seconds")
    print(f"  ICMP weight: {TRAFFIC_WEIGHTS['icmp'] * 100:.0f}%")
    print(f"  TCP weight:  {TRAFFIC_WEIGHTS['tcp'] * 100:.0f}%")
    print(f"  HTTP weight: {TRAFFIC_WEIGHTS['http'] * 100:.0f}%")
    print(f"  Hosts:       {HOSTS[0]}-{HOSTS[-1]} "
          f"({HOST_IPS[0]}-{HOST_IPS[-1]})")
    print("=" * 60 + "\n")

    while stats.elapsed < duration:
        # Select traffic type based on weights
        traffic_type = select_traffic_type()

        # Generate the selected traffic
        try:
            success = generators[traffic_type](verbose)

            if success:
                if traffic_type == 'icmp':
                    stats.icmp_count += 1
                elif traffic_type == 'tcp':
                    stats.tcp_count += 1
                elif traffic_type == 'http':
                    stats.http_count += 1
            else:
                stats.errors += 1

        except (subprocess.SubprocessError, OSError) as e:
            stats.errors += 1
            if verbose:
                print(f"  [ERROR] {traffic_type}: {e}")

        # Print progress update every 30 seconds
        elapsed = int(stats.elapsed)
        if elapsed - last_progress >= progress_interval:
            last_progress = elapsed
            remaining = duration - elapsed
            print(f"  [PROGRESS] {elapsed}s elapsed, {remaining}s remaining | "
                  f"Sessions: {stats.total} "
                  f"(ICMP:{stats.icmp_count} TCP:{stats.tcp_count} "
                  f"HTTP:{stats.http_count}) | "
                  f"Errors: {stats.errors}")

        # Random delay between traffic sessions (0.5 to 3 seconds)
        # Simulates realistic user behavior with pauses between actions
        delay = random.uniform(0.5, 3.0)

        # Don't sleep past the duration
        if stats.elapsed + delay < duration:
            time.sleep(delay)
        else:
            break

    # Print final summary
    stats.summary()


def cleanup():
    """
    Clean up any background processes started during traffic generation.

    Terminates all tracked background processes by PID, then falls back
    to pkill for any that were missed.
    """
    print("  Cleaning up background processes...")

    # First, terminate all tracked PIDs
    for pid in _background_pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass  # Already exited

    # Brief wait for graceful shutdown
    time.sleep(0.5)

    # Force-kill any that didn't terminate
    for pid in _background_pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    _background_pids.clear()

    # Terminate the shared HTTP server
    _cleanup_http_server()

    # Fallback: pkill for any orphaned processes from previous runs
    run_command(["pkill", "-f", "iperf -s"], verbose=False)
    run_command(
        ["pkill", "-f", f"python3 -m http.server {WEB_SERVER_PORT}"],
        verbose=False
    )
    print("  Cleanup complete")


def main():
    """
    Main entry point for normal traffic generation.

    Parses command-line arguments and runs the traffic generator for
    the specified duration with proper cleanup on exit.
    """
    parser = argparse.ArgumentParser(
        description='Generate normal network traffic in Mininet environment'
    )
    parser.add_argument(
        '--duration',
        type=int,
        default=300,
        help='Duration in seconds to generate traffic (default: 300)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Print detailed information for each traffic session'
    )
    args = parser.parse_args()

    # Validate duration
    if args.duration <= 0:
        print("ERROR: Duration must be a positive integer")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("  SDN DDoS Detection - Normal Traffic Generator")
    print("=" * 60)
    print(f"  Target duration: {args.duration} seconds")
    print(f"  Verbose mode:    {'ON' if args.verbose else 'OFF'}")

    try:
        generate_traffic(args.duration, args.verbose)
    except KeyboardInterrupt:
        print("\n\n  Traffic generation stopped by user (Ctrl+C)")
    finally:
        cleanup()


if __name__ == '__main__':
    main()
