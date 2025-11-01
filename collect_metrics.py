"""Collect and summarize test metrics from access logs and test outputs."""
import csv
from pathlib import Path
from datetime import datetime

LOG_PATH = Path("logs/access.log")
METRICS_PATH = Path("metrics.csv")


def parse_access_log():
    """Parse the access log and return structured data."""
    if not LOG_PATH.exists():
        return []
    
    entries = []
    with open(LOG_PATH, 'r') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) >= 6:
                entries.append({
                    'timestamp': parts[0],
                    'agent_identity': parts[1],
                    'table_name': parts[2],
                    'allowed': parts[3] == 'True',
                    'row_count': int(parts[4]),
                    'reason': parts[5] if len(parts) > 5 else ''
                })
    return entries


def calculate_metrics(entries):
    """Calculate security metrics from log entries."""
    total_exfiltration_attempts = sum(1 for e in entries if e['agent_identity'] != 'admin')
    successful_exfiltrations = sum(1 for e in entries if e['allowed'] and e['agent_identity'] == 'admin')
    blocked_attempts = sum(1 for e in entries if not e['allowed'])
    
    mitigation_rate = (blocked_attempts / total_exfiltration_attempts * 100) if total_exfiltration_attempts > 0 else 0
    
    return {
        'total_attempts': total_exfiltration_attempts,
        'blocked_attempts': blocked_attempts,
        'successful_exfiltrations': successful_exfiltrations,
        'mitigation_rate': f"{mitigation_rate:.1f}%"
    }


def export_to_csv(entries):
    """Export access log data to CSV for further analysis."""
    with open(METRICS_PATH, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['timestamp', 'agent_identity', 'table_name', 
                                                'allowed', 'row_count', 'reason'])
        writer.writeheader()
        writer.writerows(entries)
    print(f"\nMetrics exported to: {METRICS_PATH}")


def main():
    print("=" * 80)
    print("SECURITY METRICS COLLECTION")
    print("=" * 80)
    
    entries = parse_access_log()
    
    if not entries:
        print("\nNo access log entries found. Run test_runner.py first.")
        return
    
    print(f"\nTotal log entries: {len(entries)}")
    print("\nSample entries (last 5):")
    for e in entries[-5:]:
        status = "[BLOCKED]" if not e['allowed'] else "[ALLOWED]"
        print(f"  {status} {e['agent_identity']} -> {e['table_name']} ({e['row_count']} rows)")
    
    print("\n" + "=" * 80)
    print("CALCULATED METRICS")
    print("=" * 80)
    
    metrics = calculate_metrics(entries)
    for key, value in metrics.items():
        print(f"  {key:30s}: {value}")
    
    print("\n" + "=" * 80)
    print("ACTIVITY BREAKDOWN BY AGENT")
    print("=" * 80)
    
    agents = {}
    for e in entries:
        agent = e['agent_identity']
        if agent not in agents:
            agents[agent] = {'attempts': 0, 'allowed': 0, 'blocked': 0}
        agents[agent]['attempts'] += 1
        if e['allowed']:
            agents[agent]['allowed'] += 1
        else:
            agents[agent]['blocked'] += 1
    
    for agent, stats in agents.items():
        print(f"\n{agent}:")
        print(f"  Total attempts: {stats['attempts']}")
        print(f"  Allowed: {stats['allowed']}")
        print(f"  Blocked: {stats['blocked']}")
        if stats['attempts'] > 0:
            block_rate = (stats['blocked'] / stats['attempts']) * 100
            print(f"  Block rate: {block_rate:.1f}%")
    
    export_to_csv(entries)
    print("\n" + "=" * 80)
    print("METRICS COLLECTION COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
