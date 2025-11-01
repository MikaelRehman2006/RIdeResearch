"""Test runner demonstrating VULNERABLE configuration (agent with admin access)."""
from services.mock_db import safe_query
import json

print("=" * 80)
print("VULNERABLE CONFIGURATION TEST - Agent with admin access")
print("=" * 80)
print()

# Simulating a vulnerable scenario where agent has admin privileges
agent_identity = "admin"  # VULNERABLE: agent has admin access

samples = [
    "user_data",
    "payment_info",
    "transaction_logs"
]

for table in samples:
    print(f"\n{'=' * 80}")
    print(f"Attempting to access: {table}")
    print("=" * 80)
    try:
        rows = safe_query(table, agent_identity=agent_identity, require_sensitive=True)
        if rows:
            print(f"[OK] ACCESS GRANTED - Retrieved {len(rows)} sensitive rows:")
            for row in rows[:3]:  # Show first 3 rows
                print(json.dumps(row, indent=2))
            if len(rows) > 3:
                print(f"... and {len(rows) - 3} more rows")
    except PermissionError as e:
        print(f"[X] {e}")
    print()

print("=" * 80)
print("This demonstrates a VULNERABILITY - agent should not have admin access!")
print("Check logs/access.log for the successful access records.")
print("=" * 80)
