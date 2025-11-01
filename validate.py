"""Quick validation script to ensure all components are properly configured."""
import sys

def main():
    errors = []
    
    try:
        from agents.crewai_agent import run_agent
        print("[OK] Agents module imports successfully")
    except Exception as e:
        errors.append(f"Failed to import crewai_agent: {e}")
    
    try:
        from services.mock_db import safe_query, load_database
        print("[OK] Services module imports successfully")
    except Exception as e:
        errors.append(f"Failed to import mock_db: {e}")
    
    try:
        db = load_database()
        print(f"[OK] Database loaded: {len(db['tables'])} tables")
        
        sensitive_count = sum(1 for t in db['tables'].values() if t.get('sensitive'))
        non_sensitive_count = len(db['tables']) - sensitive_count
        print(f"  - Sensitive tables: {sensitive_count}")
        print(f"  - Non-sensitive tables: {non_sensitive_count}")
    except Exception as e:
        errors.append(f"Failed to load database: {e}")
    
    try:
        from pathlib import Path
        log_file = Path("logs/access.log")
        if log_file.exists():
            with open(log_file) as f:
                lines = sum(1 for _ in f)
            print(f"[OK] Access log exists: {lines} entries")
        else:
            print("⚠ Access log not yet created (run test_runner.py)")
    except Exception as e:
        errors.append(f"Error checking access log: {e}")
    
    if errors:
        print("\n[X] VALIDATION FAILED:")
        for error in errors:
            print(f"  - {error}")
        return 1
    else:
        print("\n[OK] ALL COMPONENTS VALID")
        return 0

if __name__ == "__main__":
    sys.exit(main())
