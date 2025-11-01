import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

DB_PATH = Path("data/db.json")
LOG_PATH = Path("logs/access.log")


def load_database() -> Dict:
    """Load the mock database from JSON file."""
    with open(DB_PATH, 'r') as f:
        return json.load(f)


def log_access(
    agent_identity: str,
    table_name: str,
    allowed: bool,
    row_count: int,
    reason: str = ""
):
    """Log database access attempts to the access log."""
    LOG_PATH.parent.mkdir(exist_ok=True)
    
    timestamp = datetime.now().isoformat()
    log_entry = f"{timestamp}\t{agent_identity}\t{table_name}\t{allowed}\t{row_count}\t{reason}\n"
    
    with open(LOG_PATH, 'a') as f:
        f.write(log_entry)


def safe_query(
    table_name: str,
    agent_identity: str = "unknown",
    require_sensitive: bool = False
) -> Optional[List[Dict]]:
    """
    Query a table with access control based on sensitive flag and agent identity.
    
    Args:
        table_name: Name of the table to query
        agent_identity: Identity of the agent making the request
        require_sensitive: Whether the query requires access to sensitive data
    
    Returns:
        List of rows if access granted, None if denied
    """
    db = load_database()
    
    if table_name not in db["tables"]:
        reason = f"Table not found: {table_name}"
        log_access(agent_identity, table_name, False, 0, reason)
        return None
    
    table = db["tables"][table_name]
    is_sensitive = table["sensitive"]
    
    # Policy enforcement: only 'admin' can access sensitive tables
    if is_sensitive or require_sensitive:
        if agent_identity != "admin":
            reason = f"Access denied to sensitive table: {table_name}"
            log_access(agent_identity, table_name, False, 0, reason)
            raise PermissionError(reason)
    
    # Access granted
    row_count = len(table["rows"])
    log_access(agent_identity, table_name, True, row_count, "Access granted")
    return table["rows"]


def query_table(table_name: str, agent_identity: str = "unknown") -> Optional[List[Dict]]:
    """
    Query a table without special sensitivity requirement.
    Uses safe_query internally.
    """
    return safe_query(table_name, agent_identity, require_sensitive=False)
