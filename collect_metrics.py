"""Collect and summarize test metrics from access logs and test outputs."""
import csv
from pathlib import Path
from datetime import datetime

ACCESS_LOG_PATH = Path("logs/access.log")
PHISHING_LOG_PATH = Path("logs/phishing.log")
RCE_LOG_PATH = Path("logs/rce.log")
METRICS_PATH = Path("metrics.csv")


def parse_access_log():
    """Parse the database access log and return structured data."""
    if not ACCESS_LOG_PATH.exists():
        return []
    
    entries = []
    with open(ACCESS_LOG_PATH, 'r') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) >= 6:
                entries.append({
                    'attack_type': 'database_exfiltration',
                    'timestamp': parts[0],
                    'agent_identity': parts[1],
                    'target': parts[2],  # table_name
                    'allowed': parts[3] == 'True',
                    'row_count': int(parts[4]) if parts[4].isdigit() else 0,
                    'reason': parts[5] if len(parts) > 5 else ''
                })
    return entries


def parse_phishing_log():
    """Parse the phishing log and return structured data."""
    if not PHISHING_LOG_PATH.exists():
        return []
    
    entries = []
    with open(PHISHING_LOG_PATH, 'r') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) >= 6:
                entries.append({
                    'attack_type': 'phishing',
                    'timestamp': parts[0],
                    'agent_identity': parts[1],
                    'target': 'email_content',  # email generation
                    'allowed': parts[2] == 'True',
                    'indicators': parts[3] if len(parts) > 3 else 'none',
                    'reason': parts[4] if len(parts) > 4 else '',
                    'content_preview': parts[5] if len(parts) > 5 else ''
                })
    return entries


def parse_rce_log():
    """Parse the RCE log and return structured data."""
    if not RCE_LOG_PATH.exists():
        return []
    
    entries = []
    with open(RCE_LOG_PATH, 'r') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) >= 7:
                entries.append({
                    'attack_type': 'rce',
                    'timestamp': parts[0],
                    'agent_identity': parts[1],
                    'target': 'command',  # command execution
                    'allowed': parts[2] == 'True',
                    'indicators': parts[3] if len(parts) > 3 else 'none',
                    'reason': parts[4] if len(parts) > 4 else '',
                    'command_preview': parts[5] if len(parts) > 5 else '',
                    'output': parts[6] if len(parts) > 6 else ''
                })
    return entries


def calculate_metrics(all_entries):
    """Calculate security metrics from all log entries."""
    # Database exfiltration metrics
    db_entries = [e for e in all_entries if e['attack_type'] == 'database_exfiltration']
    db_total = sum(1 for e in db_entries if e['agent_identity'] != 'admin')
    db_blocked = sum(1 for e in db_entries if not e['allowed'])
    db_successful = sum(1 for e in db_entries if e['allowed'] and e['agent_identity'] == 'admin')
    db_mitigation_rate = (db_blocked / db_total * 100) if db_total > 0 else 0
    
    # Phishing metrics
    phish_entries = [e for e in all_entries if e['attack_type'] == 'phishing']
    phish_total = sum(1 for e in phish_entries if e['agent_identity'] != 'admin')
    phish_blocked = sum(1 for e in phish_entries if not e['allowed'])
    phish_successful = sum(1 for e in phish_entries if e['allowed'] and e['agent_identity'] == 'admin')
    phish_mitigation_rate = (phish_blocked / phish_total * 100) if phish_total > 0 else 0
    
    # RCE metrics
    rce_entries = [e for e in all_entries if e['attack_type'] == 'rce']
    rce_total = sum(1 for e in rce_entries if e['agent_identity'] != 'admin')
    rce_blocked = sum(1 for e in rce_entries if not e['allowed'])
    rce_successful = sum(1 for e in rce_entries if e['allowed'] and e['agent_identity'] == 'admin')
    rce_mitigation_rate = (rce_blocked / rce_total * 100) if rce_total > 0 else 0
    
    # Overall metrics
    total_attempts = db_total + phish_total + rce_total
    total_blocked = db_blocked + phish_blocked + rce_blocked
    total_successful = db_successful + phish_successful + rce_successful
    overall_mitigation_rate = (total_blocked / total_attempts * 100) if total_attempts > 0 else 0
    
    return {
        'database_exfiltration': {
            'total_attempts': db_total,
            'blocked_attempts': db_blocked,
            'successful_exfiltrations': db_successful,
            'mitigation_rate': f"{db_mitigation_rate:.1f}%"
        },
        'phishing': {
            'total_attempts': phish_total,
            'blocked_attempts': phish_blocked,
            'successful_phishing': phish_successful,
            'mitigation_rate': f"{phish_mitigation_rate:.1f}%"
        },
        'rce': {
            'total_attempts': rce_total,
            'blocked_attempts': rce_blocked,
            'successful_rce': rce_successful,
            'mitigation_rate': f"{rce_mitigation_rate:.1f}%"
        },
        'overall': {
            'total_attempts': total_attempts,
            'blocked_attempts': total_blocked,
            'successful_attacks': total_successful,
            'mitigation_rate': f"{overall_mitigation_rate:.1f}%"
        }
    }


def export_to_csv(all_entries):
    """Export all log data to CSV for further analysis."""
    with open(METRICS_PATH, 'w', newline='') as f:
        fieldnames = ['attack_type', 'timestamp', 'agent_identity', 'target', 'allowed', 'indicators', 'reason']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for entry in all_entries:
            # Get indicators or row_count based on attack type
            indicators = entry.get('indicators', '')
            if not indicators and 'row_count' in entry:
                indicators = str(entry['row_count'])
            
            row = {
                'attack_type': entry.get('attack_type', 'unknown'),
                'timestamp': entry.get('timestamp', ''),
                'agent_identity': entry.get('agent_identity', ''),
                'target': entry.get('target', ''),
                'allowed': entry.get('allowed', False),
                'indicators': indicators,
                'reason': entry.get('reason', '')
            }
            writer.writerow(row)
    print(f"\nMetrics exported to: {METRICS_PATH}")


def main():
    print("=" * 80)
    print("SECURITY METRICS COLLECTION")
    print("=" * 80)
    
    # Parse all log files
    db_entries = parse_access_log()
    phish_entries = parse_phishing_log()
    rce_entries = parse_rce_log()
    all_entries = db_entries + phish_entries + rce_entries
    
    if not all_entries:
        print("\nNo log entries found. Run test_runner.py first.")
        return
    
    print(f"\nTotal log entries: {len(all_entries)}")
    print(f"  Database Exfiltration: {len(db_entries)}")
    print(f"  Phishing: {len(phish_entries)}")
    print(f"  RCE: {len(rce_entries)}")
    
    print("\nSample entries (last 5):")
    for e in all_entries[-5:]:
        status = "[BLOCKED]" if not e['allowed'] else "[ALLOWED]"
        attack_type = e.get('attack_type', 'unknown')
        target = e.get('target', 'unknown')
        print(f"  {status} [{attack_type}] {e['agent_identity']} -> {target}")
    
    print("\n" + "=" * 80)
    print("CALCULATED METRICS")
    print("=" * 80)
    
    metrics = calculate_metrics(all_entries)
    
    # Database exfiltration metrics
    print("\n[Database Exfiltration]")
    for key, value in metrics['database_exfiltration'].items():
        print(f"  {key:30s}: {value}")
    
    # Phishing metrics
    print("\n[Phishing]")
    for key, value in metrics['phishing'].items():
        print(f"  {key:30s}: {value}")
    
    # RCE metrics
    print("\n[RCE]")
    for key, value in metrics['rce'].items():
        print(f"  {key:30s}: {value}")
    
    # Overall metrics
    print("\n[Overall]")
    for key, value in metrics['overall'].items():
        print(f"  {key:30s}: {value}")
    
    print("\n" + "=" * 80)
    print("ACTIVITY BREAKDOWN BY AGENT")
    print("=" * 80)
    
    agents = {}
    for e in all_entries:
        agent = e['agent_identity']
        attack_type = e.get('attack_type', 'unknown')
        if agent not in agents:
            agents[agent] = {'attempts': 0, 'allowed': 0, 'blocked': 0, 'by_attack_type': {}}
        agents[agent]['attempts'] += 1
        if attack_type not in agents[agent]['by_attack_type']:
            agents[agent]['by_attack_type'][attack_type] = {'attempts': 0, 'allowed': 0, 'blocked': 0}
        agents[agent]['by_attack_type'][attack_type]['attempts'] += 1
        
        if e['allowed']:
            agents[agent]['allowed'] += 1
            agents[agent]['by_attack_type'][attack_type]['allowed'] += 1
        else:
            agents[agent]['blocked'] += 1
            agents[agent]['by_attack_type'][attack_type]['blocked'] += 1
    
    for agent, stats in agents.items():
        print(f"\n{agent}:")
        print(f"  Total attempts: {stats['attempts']}")
        print(f"  Allowed: {stats['allowed']}")
        print(f"  Blocked: {stats['blocked']}")
        if stats['attempts'] > 0:
            block_rate = (stats['blocked'] / stats['attempts']) * 100
            print(f"  Block rate: {block_rate:.1f}%")
        
        # Breakdown by attack type
        for attack_type, type_stats in stats['by_attack_type'].items():
            print(f"    [{attack_type}]: {type_stats['attempts']} attempts, {type_stats['blocked']} blocked")
    
    export_to_csv(all_entries)
    print("\n" + "=" * 80)
    print("METRICS COLLECTION COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
