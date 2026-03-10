#!/usr/bin/env python3
"""
System Performance Monitor for SDN DDoS Detection

Monitors resource usage of the Ryu SDN controller process and collects
metrics at configurable intervals. Tracks CPU usage, memory consumption,
active flow counts, and attack detection rates. Saves all measurements
to logs/performance_metrics.csv and prints a real-time console table.

Monitored Metrics:
    - CPU usage (%) of the Ryu controller process
    - Memory usage (MB) of the Ryu controller process
    - Active OpenFlow flows across all switches
    - Cumulative attacks detected (from attacks_log.csv)
    - Average detection latency estimate (ms)

Output:
    - Real-time console table updated each interval
    - ../logs/performance_metrics.csv with all measurements
    - Summary report printed at end

Usage:
    cd utilities
    python3 performance_monitor.py --duration 3600 --interval 10

    Monitor for 10 minutes with 5-second sampling:
    python3 performance_monitor.py --duration 600 --interval 5

Requirements:
    - psutil library (pip install psutil)
    - Ryu controller must be running for process metrics
    - ovs-ofctl must be available for flow counts

"""

import psutil
import os
import time
import csv
import argparse
import subprocess
import sys
from datetime import datetime


# Resolve paths relative to this script's directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR, '..', 'logs')
PERF_LOG = os.path.join(LOG_DIR, 'performance_metrics.csv')
ATTACKS_LOG = os.path.join(LOG_DIR, 'attacks_log.csv')

# CSV headers for performance metrics
CSV_HEADERS = [
    'timestamp',
    'cpu_percent',
    'memory_mb',
    'active_flows',
    'attacks_detected',
    'avg_latency_ms'
]

# Switch names matching network_topology/topology.py
# s1, s2 = spine switches; s3, s4, s5 = leaf switches
SWITCHES = ['s1', 's2', 's3', 's4', 's5']


def find_ryu_process():
    """
    Find the running Ryu controller process.

    Searches for a process whose command line contains 'ryu-manager'
    to identify the SDN controller.

    Returns:
        psutil.Process or None: The Ryu controller process object,
            or None if not found.
    """
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = proc.info.get('cmdline', [])
            if cmdline and any('ryu-manager' in arg for arg in cmdline):
                return psutil.Process(proc.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return None


def get_cpu_usage(process):
    """
    Get CPU usage percentage for the controller process.

    Args:
        process (psutil.Process or None): Controller process object.

    Returns:
        float: CPU usage as a percentage (0.0-100.0), or 0.0 if
            process is not available.
    """
    if process is None:
        return 0.0

    try:
        return process.cpu_percent(interval=None)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 0.0


def get_memory_usage(process):
    """
    Get memory usage in MB for the controller process.

    Args:
        process (psutil.Process or None): Controller process object.

    Returns:
        float: Resident set size (RSS) memory in megabytes,
            or 0.0 if process is not available.
    """
    if process is None:
        return 0.0

    try:
        mem_info = process.memory_info()
        return mem_info.rss / (1024 * 1024)  # Convert bytes to MB
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 0.0


def get_active_flows():
    """
    Count total active OpenFlow flows across all switches.

    Uses ovs-ofctl to query flow tables on each switch defined
    in the topology. Sums flow counts across all switches.

    Returns:
        int: Total number of active flows, or 0 if ovs-ofctl
            is not available or switches are not running.
    """
    total_flows = 0

    for switch in SWITCHES:
        try:
            result = subprocess.run(
                ['ovs-ofctl', 'dump-flows', switch],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Each non-empty line (except the header) is a flow entry
                lines = result.stdout.strip().split('\n')
                # First line is the header "NXST_FLOW reply..."
                flow_count = max(len(lines) - 1, 0)
                total_flows += flow_count
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue

    return total_flows


def get_attacks_detected():
    """
    Count total attacks detected from the attacks log.

    Reads attacks_log.csv and counts data rows (excluding the header).

    Returns:
        int: Total number of attack records logged, or 0 if the
            log file doesn't exist or is empty.
    """
    if not os.path.isfile(ATTACKS_LOG):
        return 0

    try:
        with open(ATTACKS_LOG, 'r') as f:
            # Count lines minus the header row
            line_count = sum(1 for _ in f) - 1
            return max(line_count, 0)
    except IOError:
        return 0


def estimate_latency(prev_attacks, curr_attacks, interval):
    """
    Estimate average detection latency based on attack detection rate.

    Provides a rough latency estimate based on the polling interval
    and detection rate. Since flow stats are polled every 5 seconds,
    average detection latency is approximately half the polling interval
    plus processing time.

    Args:
        prev_attacks (int): Attack count from previous sample.
        curr_attacks (int): Attack count from current sample.
        interval (int): Sampling interval in seconds.

    Returns:
        float: Estimated average detection latency in milliseconds.
    """
    new_attacks = curr_attacks - prev_attacks

    if new_attacks > 0:
        # Detection happened within this interval
        # Flow stats poll every 5s, so avg wait is ~2.5s + processing
        # Processing estimated at ~50-200ms depending on flow count
        base_latency = 2500.0  # 2.5s average wait for next poll
        processing = 150.0     # Estimated ML prediction time
        return base_latency + processing
    else:
        # No new detections; report baseline polling latency
        return 5000.0  # 5s polling interval as baseline


def init_csv():
    """
    Initialize the performance metrics CSV file with headers.

    Creates the log directory if it doesn't exist and writes
    the header row if the file is new or empty.
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    if not os.path.isfile(PERF_LOG):
        with open(PERF_LOG, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADERS)
    else:
        # Check if file is empty (no header)
        try:
            with open(PERF_LOG, 'r') as f:
                first_line = f.readline().strip()
            if not first_line:
                with open(PERF_LOG, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(CSV_HEADERS)
        except IOError:
            pass


def write_metric(timestamp, cpu, memory, flows, attacks, latency):
    """
    Append a single metric record to the performance CSV.

    Args:
        timestamp (str): Formatted timestamp string.
        cpu (float): CPU usage percentage.
        memory (float): Memory usage in MB.
        flows (int): Active flow count.
        attacks (int): Total attacks detected.
        latency (float): Estimated detection latency in ms.
    """
    try:
        with open(PERF_LOG, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp,
                f'{cpu:.1f}',
                f'{memory:.1f}',
                flows,
                attacks,
                f'{latency:.1f}'
            ])
    except IOError as e:
        print(f"  [ERROR] Failed to write metrics: {e}")


def print_table_header():
    """Print the column headers for the real-time console table."""
    print()
    print("  " + "-" * 78)
    print(f"  {'Timestamp':<22s} {'CPU %':>7s} {'Mem MB':>8s} "
          f"{'Flows':>7s} {'Attacks':>9s} {'Latency ms':>11s}")
    print("  " + "-" * 78)


def print_table_row(timestamp, cpu, memory, flows, attacks, latency):
    """
    Print a single row of the real-time metrics table.

    Args:
        timestamp (str): Formatted timestamp.
        cpu (float): CPU usage percentage.
        memory (float): Memory in MB.
        flows (int): Active flows.
        attacks (int): Attacks detected.
        latency (float): Latency in ms.
    """
    print(f"  {timestamp:<22s} {cpu:>7.1f} {memory:>8.1f} "
          f"{flows:>7d} {attacks:>9d} {latency:>11.1f}")


def print_summary(metrics_history):
    """
    Print a comprehensive summary of all collected metrics.

    Calculates averages, peaks, and minimums from the collected
    metrics history and prints a formatted report.

    Args:
        metrics_history (list): List of metric dictionaries, each
            containing cpu, memory, flows, attacks, latency.
    """
    if not metrics_history:
        print("\n  No metrics collected.")
        return

    cpus = [m['cpu'] for m in metrics_history]
    mems = [m['memory'] for m in metrics_history]
    flows = [m['flows'] for m in metrics_history]
    attacks_list = [m['attacks'] for m in metrics_history]
    latencies = [m['latency'] for m in metrics_history]

    print("\n" + "=" * 65)
    print("  Performance Monitoring Summary")
    print("=" * 65)

    print(f"\n  Duration:          {len(metrics_history)} samples collected")
    print(f"  First sample:      {metrics_history[0]['timestamp']}")
    print(f"  Last sample:       {metrics_history[-1]['timestamp']}")

    print(f"\n  CPU Usage:")
    print(f"    Average:   {sum(cpus) / len(cpus):>8.1f} %")
    print(f"    Peak:      {max(cpus):>8.1f} %")
    print(f"    Minimum:   {min(cpus):>8.1f} %")

    print(f"\n  Memory Usage:")
    print(f"    Average:   {sum(mems) / len(mems):>8.1f} MB")
    print(f"    Peak:      {max(mems):>8.1f} MB")
    print(f"    Minimum:   {min(mems):>8.1f} MB")

    print(f"\n  Active Flows:")
    print(f"    Average:   {sum(flows) / len(flows):>8.0f}")
    print(f"    Peak:      {max(flows):>8d}")
    print(f"    Minimum:   {min(flows):>8d}")

    print(f"\n  Attacks Detected:")
    print(f"    Total:     {max(attacks_list):>8d}")
    new_attacks = max(attacks_list) - min(attacks_list)
    print(f"    This session: {new_attacks:>5d}")

    print(f"\n  Detection Latency:")
    print(f"    Average:   {sum(latencies) / len(latencies):>8.1f} ms")
    print(f"    Peak:      {max(latencies):>8.1f} ms")
    print(f"    Minimum:   {min(latencies):>8.1f} ms")

    print(f"\n  Metrics saved to: {PERF_LOG}")
    print("=" * 65 + "\n")


def monitor(duration, interval):
    """
    Main monitoring loop.

    Collects system metrics at the specified interval for the given
    duration. Displays a real-time table and saves all data to CSV.

    Args:
        duration (int): Total monitoring duration in seconds.
        interval (int): Sampling interval in seconds.
    """
    # Initialize CSV
    init_csv()

    # Find the Ryu controller process
    print("\n  Searching for Ryu controller process...")
    ryu_proc = find_ryu_process()

    if ryu_proc:
        print(f"  [OK] Found Ryu controller (PID: {ryu_proc.pid})")
        # Prime the CPU measurement (first call returns 0.0)
        try:
            ryu_proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    else:
        print("  [WARN] Ryu controller process not found")
        print("         CPU and memory will show 0.0")
        print("         Start controller: cd sdn_controller && ryu-manager mitigation_module.py")

    # Print monitoring configuration
    print(f"\n  Monitoring configuration:")
    print(f"    Duration:  {duration} seconds")
    print(f"    Interval:  {interval} seconds")
    print(f"    Samples:   ~{duration // interval}")
    print(f"    Output:    {PERF_LOG}")

    # Print table header
    print_table_header()

    # Collection loop
    metrics_history = []
    prev_attacks = get_attacks_detected()
    elapsed = 0

    try:
        while elapsed < duration:
            # Collect timestamp
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Re-check for controller process if previously not found
            if ryu_proc is None or not ryu_proc.is_running():
                ryu_proc = find_ryu_process()
                if ryu_proc:
                    ryu_proc.cpu_percent(interval=None)

            # Collect metrics
            cpu = get_cpu_usage(ryu_proc)
            memory = get_memory_usage(ryu_proc)
            flows = get_active_flows()
            attacks = get_attacks_detected()
            latency = estimate_latency(prev_attacks, attacks, interval)

            # Print row
            print_table_row(timestamp, cpu, memory, flows, attacks, latency)

            # Save to CSV
            write_metric(timestamp, cpu, memory, flows, attacks, latency)

            # Store in history
            metrics_history.append({
                'timestamp': timestamp,
                'cpu': cpu,
                'memory': memory,
                'flows': flows,
                'attacks': attacks,
                'latency': latency
            })

            # Update state
            prev_attacks = attacks
            elapsed += interval

            # Wait for next sample (unless we've exceeded duration)
            if elapsed < duration:
                time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n  [STOP] Monitoring stopped by user (Ctrl+C)")

    # Print closing line and summary
    print("  " + "-" * 78)
    print_summary(metrics_history)


def main():
    """
    Main entry point for the performance monitor.

    Parses command-line arguments and starts the monitoring loop.
    """
    parser = argparse.ArgumentParser(
        description='Monitor SDN controller performance metrics'
    )
    parser.add_argument(
        '--duration',
        type=int,
        default=3600,
        help='Monitoring duration in seconds (default: 3600)'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=10,
        help='Sampling interval in seconds (default: 10)'
    )
    args = parser.parse_args()

    # Validate arguments
    if args.duration <= 0:
        print("ERROR: Duration must be a positive integer")
        sys.exit(1)

    if args.interval <= 0:
        print("ERROR: Interval must be a positive integer")
        sys.exit(1)

    if args.interval > args.duration:
        print("ERROR: Interval cannot exceed duration")
        sys.exit(1)

    # Print banner
    print("\n" + "=" * 65)
    print("  SDN DDoS Detection - Performance Monitor")
    print("=" * 65)

    # Check psutil is working
    try:
        psutil.cpu_percent(interval=None)
    except Exception as e:
        print(f"  [ERROR] psutil initialization failed: {e}")
        sys.exit(1)

    # Start monitoring
    monitor(args.duration, args.interval)


if __name__ == '__main__':
    main()
