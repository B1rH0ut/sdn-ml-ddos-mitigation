#!/usr/bin/env python3
"""
Log Analysis and Reporting for SDN DDoS Detection System

Analyzes attack detection logs and performance metrics collected during
system operation. Generates a console summary, a detailed text report,
and optional visualizations.

Input Files (in this directory):
    - attacks_log.csv:         Attack detection records from controller
    - performance_metrics.csv: System resource measurements from monitor

Output Files:
    - detection_report.txt:    Detailed analysis report
    - attack_timeline.png:     Attacks over time (optional)
    - attack_types.png:        Attack type distribution (optional)
    - resource_usage.png:      CPU/Memory over time (optional)

Usage:
    cd logs
    python3 analyze_logs.py
    python3 analyze_logs.py --no-plots

"""

import pandas as pd
import os
import sys
import argparse
from datetime import datetime

# Attempt to import visualization libraries
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

try:
    import seaborn as sns
    HAS_SEABORN = True
except ImportError:
    HAS_SEABORN = False

# Resolve paths relative to this script's directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ATTACKS_LOG = os.path.join(SCRIPT_DIR, 'attacks_log.csv')
PERF_LOG = os.path.join(SCRIPT_DIR, 'performance_metrics.csv')
REPORT_FILE = os.path.join(SCRIPT_DIR, 'detection_report.txt')


# =============================================================================
# Attack Log Analysis
# =============================================================================

def load_attacks_log():
    """
    Load and parse the attacks_log.csv file.

    Returns:
        pandas.DataFrame or None: Parsed attack records with timestamp
            converted to datetime, or None if file is empty/missing.
    """
    if not os.path.isfile(ATTACKS_LOG):
        print(f"  [WARN] Attacks log not found: {ATTACKS_LOG}")
        return None

    try:
        df = pd.read_csv(ATTACKS_LOG)
    except pd.errors.EmptyDataError:
        print(f"  [WARN] Attacks log is empty: {ATTACKS_LOG}")
        return None

    if len(df) == 0:
        print(f"  [INFO] No attack records in: {ATTACKS_LOG}")
        return None

    # Parse timestamp column
    try:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    except (KeyError, ValueError):
        print("  [WARN] Could not parse timestamps in attacks log")

    print(f"  [OK] Loaded {len(df)} attack records")
    return df


def analyze_attacks(df):
    """
    Perform comprehensive analysis of attack detection records.

    Args:
        df (pandas.DataFrame): Attack records with columns:
            timestamp, src_ip, dst_ip, attack_type, packet_rate, action, switch

    Returns:
        dict: Analysis results containing totals, breakdowns, and statistics.
    """
    results = {}

    # --- Total attacks ---
    results['total'] = len(df)

    # --- Time range ---
    if pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        results['first_attack'] = df['timestamp'].min().strftime('%Y-%m-%d %H:%M:%S')
        results['last_attack'] = df['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
        duration = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
        results['duration_sec'] = round(duration, 1)
    else:
        results['first_attack'] = str(df['timestamp'].iloc[0])
        results['last_attack'] = str(df['timestamp'].iloc[-1])
        results['duration_sec'] = 0

    # --- By attack type ---
    type_counts = df['attack_type'].value_counts().to_dict()
    results['by_type'] = type_counts

    # --- By source IP ---
    src_counts = df['src_ip'].value_counts().to_dict()
    results['by_source'] = src_counts
    results['unique_sources'] = len(src_counts)

    # --- By destination IP ---
    dst_counts = df['dst_ip'].value_counts().to_dict()
    results['by_destination'] = dst_counts
    results['unique_destinations'] = len(dst_counts)

    # --- By switch ---
    switch_counts = df['switch'].value_counts().to_dict()
    results['by_switch'] = switch_counts

    # --- Packet rate statistics ---
    try:
        rates = pd.to_numeric(df['packet_rate'], errors='coerce').dropna()
        if len(rates) > 0:
            results['avg_packet_rate'] = round(rates.mean(), 2)
            results['max_packet_rate'] = round(rates.max(), 2)
            results['min_packet_rate'] = round(rates.min(), 2)
        else:
            results['avg_packet_rate'] = 0
            results['max_packet_rate'] = 0
            results['min_packet_rate'] = 0
    except (KeyError, ValueError):
        results['avg_packet_rate'] = 0
        results['max_packet_rate'] = 0
        results['min_packet_rate'] = 0

    # --- Hourly timeline ---
    if pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        hourly = df.set_index('timestamp').resample('h').size()
        results['hourly_counts'] = hourly.to_dict()
    else:
        results['hourly_counts'] = {}

    # --- Action breakdown ---
    action_counts = df['action'].value_counts().to_dict()
    results['by_action'] = action_counts

    return results


# =============================================================================
# Performance Metrics Analysis
# =============================================================================

def load_performance_log():
    """
    Load and parse the performance_metrics.csv file.

    Returns:
        pandas.DataFrame or None: Parsed performance records, or None
            if file is empty/missing.
    """
    if not os.path.isfile(PERF_LOG):
        print(f"  [WARN] Performance log not found: {PERF_LOG}")
        return None

    try:
        df = pd.read_csv(PERF_LOG)
    except pd.errors.EmptyDataError:
        print(f"  [WARN] Performance log is empty: {PERF_LOG}")
        return None

    if len(df) == 0:
        print(f"  [INFO] No performance records in: {PERF_LOG}")
        return None

    # Parse timestamp
    try:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    except (KeyError, ValueError):
        pass

    print(f"  [OK] Loaded {len(df)} performance records")
    return df


def analyze_performance(df):
    """
    Analyze system performance metrics.

    Args:
        df (pandas.DataFrame): Performance records with columns:
            timestamp, cpu_percent, memory_mb, active_flows,
            attacks_detected, avg_latency_ms

    Returns:
        dict: Performance statistics including averages, peaks, and trends.
    """
    results = {}

    # --- CPU usage ---
    try:
        results['avg_cpu'] = round(df['cpu_percent'].mean(), 2)
        results['peak_cpu'] = round(df['cpu_percent'].max(), 2)
        results['min_cpu'] = round(df['cpu_percent'].min(), 2)
    except KeyError:
        results['avg_cpu'] = 0
        results['peak_cpu'] = 0
        results['min_cpu'] = 0

    # --- Memory usage ---
    try:
        results['avg_memory'] = round(df['memory_mb'].mean(), 2)
        results['peak_memory'] = round(df['memory_mb'].max(), 2)
    except KeyError:
        results['avg_memory'] = 0
        results['peak_memory'] = 0

    # --- Active flows ---
    try:
        results['avg_flows'] = round(df['active_flows'].mean(), 1)
        results['peak_flows'] = int(df['active_flows'].max())
    except KeyError:
        results['avg_flows'] = 0
        results['peak_flows'] = 0

    # --- Detection latency ---
    try:
        results['avg_latency'] = round(df['avg_latency_ms'].mean(), 2)
        results['peak_latency'] = round(df['avg_latency_ms'].max(), 2)
    except KeyError:
        results['avg_latency'] = 0
        results['peak_latency'] = 0

    # --- Total attacks detected ---
    try:
        results['total_detected'] = int(df['attacks_detected'].sum())
    except KeyError:
        results['total_detected'] = 0

    # --- Measurement duration ---
    results['total_records'] = len(df)

    return results


# =============================================================================
# Console Summary
# =============================================================================

def print_console_summary(attack_results, perf_results):
    """
    Print a formatted summary to the console.

    Args:
        attack_results (dict or None): Attack analysis results.
        perf_results (dict or None): Performance analysis results.
    """
    print("\n" + "=" * 65)
    print("  SDN DDoS Detection System - Analysis Summary")
    print("=" * 65)

    # --- Attack Summary ---
    print("\n  ATTACK DETECTION SUMMARY")
    print("  " + "-" * 45)

    if attack_results:
        print(f"  Total attacks detected:  {attack_results['total']}")
        print(f"  Time range:              {attack_results['first_attack']}")
        print(f"                           {attack_results['last_attack']}")
        print(f"  Duration:                {attack_results['duration_sec']}s")
        print(f"  Unique source IPs:       {attack_results['unique_sources']}")

        print(f"\n  Attacks by Type:")
        for attack_type, count in attack_results['by_type'].items():
            pct = count / attack_results['total'] * 100
            bar = '#' * int(pct / 2)
            print(f"    {attack_type:<20s} {count:>6} ({pct:>5.1f}%) {bar}")

        print(f"\n  Top Source IPs:")
        for src_ip, count in sorted(
            attack_results['by_source'].items(),
            key=lambda x: x[1], reverse=True
        )[:10]:
            print(f"    {src_ip:<20s} {count:>6} attacks")

        print(f"\n  Attacks by Switch:")
        for switch, count in attack_results['by_switch'].items():
            print(f"    Switch {switch:<10} {count:>6} attacks")

        print(f"\n  Packet Rate Statistics:")
        print(f"    Average:  {attack_results['avg_packet_rate']:.2f} pps")
        print(f"    Maximum:  {attack_results['max_packet_rate']:.2f} pps")
        print(f"    Minimum:  {attack_results['min_packet_rate']:.2f} pps")

        # Hourly timeline
        if attack_results['hourly_counts']:
            print(f"\n  Hourly Attack Timeline:")
            for hour, count in attack_results['hourly_counts'].items():
                hour_str = hour.strftime('%Y-%m-%d %H:00') if hasattr(hour, 'strftime') else str(hour)
                bar = '#' * min(count, 50)
                print(f"    {hour_str}  {count:>4} {bar}")
    else:
        print("  No attack data available.")
        print("  Run the system to generate attack detection logs.")

    # --- Performance Summary ---
    print(f"\n  SYSTEM PERFORMANCE SUMMARY")
    print("  " + "-" * 45)

    if perf_results:
        print(f"  Total measurements:  {perf_results['total_records']}")

        print(f"\n  CPU Usage:")
        print(f"    Average:  {perf_results['avg_cpu']:.1f}%")
        print(f"    Peak:     {perf_results['peak_cpu']:.1f}%")

        print(f"\n  Memory Usage:")
        print(f"    Average:  {perf_results['avg_memory']:.1f} MB")
        print(f"    Peak:     {perf_results['peak_memory']:.1f} MB")

        print(f"\n  Flow Statistics:")
        print(f"    Avg active flows:  {perf_results['avg_flows']:.0f}")
        print(f"    Peak active flows: {perf_results['peak_flows']}")

        print(f"\n  Detection Latency:")
        print(f"    Average:  {perf_results['avg_latency']:.2f} ms")
        print(f"    Peak:     {perf_results['peak_latency']:.2f} ms")

        print(f"\n  Total attacks detected: {perf_results['total_detected']}")
    else:
        print("  No performance data available.")
        print("  Run utilities/performance_monitor.py to collect metrics.")

    print("\n" + "=" * 65)


# =============================================================================
# Report Generation
# =============================================================================

def generate_report(attack_results, perf_results):
    """
    Generate a detailed text report and save to detection_report.txt.

    Args:
        attack_results (dict or None): Attack analysis results.
        perf_results (dict or None): Performance analysis results.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    lines = []
    lines.append("=" * 70)
    lines.append("  SDN DDoS Detection System - Analysis Report")
    lines.append(f"  Generated: {timestamp}")
    lines.append("=" * 70)

    # --- Attack Analysis ---
    lines.append("")
    lines.append("SECTION 1: ATTACK DETECTION ANALYSIS")
    lines.append("-" * 50)

    if attack_results:
        lines.append(f"Total attacks detected:     {attack_results['total']}")
        lines.append(f"First attack:               {attack_results['first_attack']}")
        lines.append(f"Last attack:                {attack_results['last_attack']}")
        lines.append(f"Monitoring duration:        {attack_results['duration_sec']}s")
        lines.append(f"Unique source IPs:          {attack_results['unique_sources']}")
        lines.append(f"Unique destination IPs:     {attack_results['unique_destinations']}")

        lines.append("")
        lines.append("Attack Type Distribution:")
        for attack_type, count in attack_results['by_type'].items():
            pct = count / attack_results['total'] * 100
            lines.append(f"  {attack_type:<25s} {count:>8} ({pct:.1f}%)")

        lines.append("")
        lines.append("Source IP Analysis:")
        for src_ip, count in sorted(
            attack_results['by_source'].items(),
            key=lambda x: x[1], reverse=True
        ):
            lines.append(f"  {src_ip:<25s} {count:>8} attacks")

        lines.append("")
        lines.append("Destination IP Analysis:")
        for dst_ip, count in sorted(
            attack_results['by_destination'].items(),
            key=lambda x: x[1], reverse=True
        ):
            lines.append(f"  {dst_ip:<25s} {count:>8} attacks")

        lines.append("")
        lines.append("Switch Analysis:")
        for switch, count in attack_results['by_switch'].items():
            lines.append(f"  Switch {str(switch):<18s} {count:>8} attacks")

        lines.append("")
        lines.append("Packet Rate Statistics:")
        lines.append(f"  Average rate:  {attack_results['avg_packet_rate']:.2f} pps")
        lines.append(f"  Maximum rate:  {attack_results['max_packet_rate']:.2f} pps")
        lines.append(f"  Minimum rate:  {attack_results['min_packet_rate']:.2f} pps")

        lines.append("")
        lines.append("Mitigation Actions:")
        for action, count in attack_results['by_action'].items():
            lines.append(f"  {action:<25s} {count:>8}")

        if attack_results['hourly_counts']:
            lines.append("")
            lines.append("Hourly Attack Timeline:")
            for hour, count in attack_results['hourly_counts'].items():
                hour_str = hour.strftime('%Y-%m-%d %H:00') if hasattr(hour, 'strftime') else str(hour)
                lines.append(f"  {hour_str}  {count:>6} attacks")
    else:
        lines.append("No attack data available for analysis.")

    # --- Performance Analysis ---
    lines.append("")
    lines.append("")
    lines.append("SECTION 2: SYSTEM PERFORMANCE ANALYSIS")
    lines.append("-" * 50)

    if perf_results:
        lines.append(f"Total measurements:    {perf_results['total_records']}")

        lines.append("")
        lines.append("CPU Usage:")
        lines.append(f"  Average:   {perf_results['avg_cpu']:.1f}%")
        lines.append(f"  Peak:      {perf_results['peak_cpu']:.1f}%")
        lines.append(f"  Minimum:   {perf_results['min_cpu']:.1f}%")

        lines.append("")
        lines.append("Memory Usage:")
        lines.append(f"  Average:   {perf_results['avg_memory']:.1f} MB")
        lines.append(f"  Peak:      {perf_results['peak_memory']:.1f} MB")

        lines.append("")
        lines.append("Flow Statistics:")
        lines.append(f"  Average active flows:  {perf_results['avg_flows']:.0f}")
        lines.append(f"  Peak active flows:     {perf_results['peak_flows']}")

        lines.append("")
        lines.append("Detection Latency:")
        lines.append(f"  Average:   {perf_results['avg_latency']:.2f} ms")
        lines.append(f"  Peak:      {perf_results['peak_latency']:.2f} ms")

        lines.append("")
        lines.append(f"Total attacks detected:  {perf_results['total_detected']}")
    else:
        lines.append("No performance data available for analysis.")

    # --- Footer ---
    lines.append("")
    lines.append("")
    lines.append("=" * 70)
    lines.append("  End of Report")
    lines.append(f"  Report file: {REPORT_FILE}")
    lines.append("=" * 70)

    # Write report to file
    try:
        with open(REPORT_FILE, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        print(f"\n  [OK] Report saved: {REPORT_FILE}")
    except IOError as e:
        print(f"\n  [ERROR] Failed to save report: {e}")


# =============================================================================
# Visualizations
# =============================================================================

def generate_visualizations(attacks_df, perf_df):
    """
    Generate visualization plots from log data.

    Creates up to three plots:
    1. Attack timeline (attacks over time)
    2. Attack type pie chart
    3. Resource usage over time (CPU and memory)

    Args:
        attacks_df (pandas.DataFrame or None): Attack records.
        perf_df (pandas.DataFrame or None): Performance records.
    """
    if not HAS_MATPLOTLIB:
        print("\n  [WARN] matplotlib not installed, skipping visualizations")
        print("  Install with: pip install matplotlib seaborn")
        return

    if HAS_SEABORN:
        sns.set_style('whitegrid')

    plots_created = 0

    # --- Plot 1: Attack Timeline ---
    if attacks_df is not None and pd.api.types.is_datetime64_any_dtype(attacks_df['timestamp']):
        try:
            fig, ax = plt.subplots(figsize=(10, 5))

            # Resample by minute for fine-grained timeline
            timeline = attacks_df.set_index('timestamp').resample('min').size()

            ax.fill_between(timeline.index, timeline.values,
                            alpha=0.3, color='#F44336')
            ax.plot(timeline.index, timeline.values,
                    color='#F44336', linewidth=1.5)

            ax.set_xlabel('Time', fontsize=11)
            ax.set_ylabel('Attacks Detected', fontsize=11)
            ax.set_title('DDoS Attack Detection Timeline', fontsize=13,
                         fontweight='bold')
            ax.grid(True, alpha=0.3)

            plt.tight_layout()
            path = os.path.join(SCRIPT_DIR, 'attack_timeline.png')
            plt.savefig(path, dpi=150, bbox_inches='tight')
            plt.close(fig)
            print(f"  [OK] Saved: attack_timeline.png")
            plots_created += 1
        except Exception as e:
            print(f"  [WARN] Could not create timeline plot: {e}")

    # --- Plot 2: Attack Type Distribution ---
    if attacks_df is not None and len(attacks_df) > 0:
        try:
            fig, ax = plt.subplots(figsize=(7, 7))

            type_counts = attacks_df['attack_type'].value_counts()
            colors = ['#F44336', '#FF9800', '#2196F3', '#9E9E9E']

            wedges, texts, autotexts = ax.pie(
                type_counts.values,
                labels=type_counts.index,
                autopct='%1.1f%%',
                colors=colors[:len(type_counts)],
                startangle=90,
                textprops={'fontsize': 11}
            )

            for autotext in autotexts:
                autotext.set_fontweight('bold')

            ax.set_title('Attack Type Distribution', fontsize=13,
                         fontweight='bold')

            plt.tight_layout()
            path = os.path.join(SCRIPT_DIR, 'attack_types.png')
            plt.savefig(path, dpi=150, bbox_inches='tight')
            plt.close(fig)
            print(f"  [OK] Saved: attack_types.png")
            plots_created += 1
        except Exception as e:
            print(f"  [WARN] Could not create type distribution plot: {e}")

    # --- Plot 3: Resource Usage Over Time ---
    if perf_df is not None and len(perf_df) > 0:
        try:
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8), sharex=True)

            x_axis = range(len(perf_df))
            if pd.api.types.is_datetime64_any_dtype(perf_df['timestamp']):
                x_axis = perf_df['timestamp']

            # CPU usage
            if 'cpu_percent' in perf_df.columns:
                ax1.plot(x_axis, perf_df['cpu_percent'],
                         color='#2196F3', linewidth=1.5, label='CPU %')
                ax1.fill_between(x_axis, perf_df['cpu_percent'],
                                 alpha=0.2, color='#2196F3')
                ax1.set_ylabel('CPU Usage (%)', fontsize=11)
                ax1.set_title('System Resource Usage Over Time',
                              fontsize=13, fontweight='bold')
                ax1.legend(loc='upper right')
                ax1.grid(True, alpha=0.3)

            # Memory usage
            if 'memory_mb' in perf_df.columns:
                ax2.plot(x_axis, perf_df['memory_mb'],
                         color='#4CAF50', linewidth=1.5, label='Memory MB')
                ax2.fill_between(x_axis, perf_df['memory_mb'],
                                 alpha=0.2, color='#4CAF50')
                ax2.set_ylabel('Memory (MB)', fontsize=11)
                ax2.set_xlabel('Time', fontsize=11)
                ax2.legend(loc='upper right')
                ax2.grid(True, alpha=0.3)

            plt.tight_layout()
            path = os.path.join(SCRIPT_DIR, 'resource_usage.png')
            plt.savefig(path, dpi=150, bbox_inches='tight')
            plt.close(fig)
            print(f"  [OK] Saved: resource_usage.png")
            plots_created += 1
        except Exception as e:
            print(f"  [WARN] Could not create resource usage plot: {e}")

    if plots_created == 0:
        print("  [INFO] No visualizations generated (insufficient data)")
    else:
        print(f"  [OK] {plots_created} visualization(s) saved")


# =============================================================================
# Main
# =============================================================================

def main():
    """
    Main entry point for log analysis.

    Loads attack and performance logs, performs analysis, prints
    console summary, generates detailed report, and optionally
    creates visualizations.
    """
    parser = argparse.ArgumentParser(
        description='Analyze SDN DDoS detection system logs'
    )
    parser.add_argument(
        '--no-plots',
        action='store_true',
        help='Skip generating visualization plots'
    )
    args = parser.parse_args()

    print("\n" + "=" * 65)
    print("  SDN DDoS Detection - Log Analyzer")
    print("=" * 65)

    # --- Load data ---
    print("\n  Loading log files...")
    attacks_df = load_attacks_log()
    perf_df = load_performance_log()

    if attacks_df is None and perf_df is None:
        print("\n  No log data found to analyze.")
        print("  Expected files:")
        print(f"    {ATTACKS_LOG}")
        print(f"    {PERF_LOG}")
        print("\n  Initialize logs:  cd logs && bash init_logs.sh")
        print("  Run the system to generate log data.")
        print()
        return

    # --- Analyze ---
    print("\n  Analyzing data...")
    attack_results = analyze_attacks(attacks_df) if attacks_df is not None else None
    perf_results = analyze_performance(perf_df) if perf_df is not None else None

    # --- Console summary ---
    print_console_summary(attack_results, perf_results)

    # --- Generate report ---
    print("\n  Generating report...")
    generate_report(attack_results, perf_results)

    # --- Visualizations ---
    if not args.no_plots:
        print("\n  Generating visualizations...")
        generate_visualizations(attacks_df, perf_df)
    else:
        print("\n  [INFO] Skipping visualizations (--no-plots)")

    # --- Done ---
    print("\n" + "=" * 65)
    print("  Analysis complete!")
    print("=" * 65)
    print(f"\n  Report:  {REPORT_FILE}")
    if not args.no_plots and HAS_MATPLOTLIB:
        print(f"  Plots:   {SCRIPT_DIR}/attack_timeline.png")
        print(f"           {SCRIPT_DIR}/attack_types.png")
        print(f"           {SCRIPT_DIR}/resource_usage.png")
    print()


if __name__ == '__main__':
    main()
