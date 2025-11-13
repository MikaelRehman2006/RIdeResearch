import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, List

POLICY_PATH = Path("data/command_policy.json")
LOG_PATH = Path("logs/rce.log")


def load_command_policy() -> Dict:
    """Load command policy from JSON file."""
    with open(POLICY_PATH, 'r') as f:
        return json.load(f)


def log_command_attempt(
    agent_identity: str,
    command: str,
    allowed: bool,
    indicators_triggered: List[str],
    reason: str = "",
    simulated_output: str = ""
):
    """Log command execution attempts to the RCE log."""
    LOG_PATH.parent.mkdir(exist_ok=True)
    
    timestamp = datetime.now().isoformat()
    command_preview = command[:100] if len(command) > 100 else command
    indicators = ", ".join(indicators_triggered) if indicators_triggered else "none"
    
    log_entry = f"{timestamp}\t{agent_identity}\t{allowed}\t{indicators}\t{reason}\t{command_preview}\t{simulated_output}\n"
    
    with open(LOG_PATH, 'a') as f:
        f.write(log_entry)


def safe_execute_command(
    command: str,
    agent_identity: str = "unknown",
    allow_bypass: bool = False
) -> Dict:
    """
    Validate command for dangerous patterns.
    Simulates execution (never actually runs commands).
    
    Args:
        command: The command to validate
        agent_identity: Identity of the agent making the request
        allow_bypass: Whether to allow admin bypass (for red-team demo)
    
    Returns:
        Dict with status and simulated output if allowed
    
    Raises:
        PermissionError if dangerous command detected and not admin
    """
    policy = load_command_policy()
    indicators_triggered = []
    
    # Check 1: Allowlist patterns (safe commands)
    is_allowed = False
    for pattern in policy["allowlist_patterns"]:
        try:
            if re.match(pattern, command, re.IGNORECASE):
                is_allowed = True
                break
        except re.error:
            # Skip invalid regex patterns
            continue
    
    # Check 2: Blocked patterns (dangerous commands)
    if not is_allowed:
        pattern_names = policy.get("blocked_pattern_names", {})
        for pattern in policy["blocked_patterns"]:
            try:
                if re.search(pattern, command, re.IGNORECASE):
                    pattern_name = pattern_names.get(pattern, pattern)
                    if pattern_name not in indicators_triggered:
                        indicators_triggered.append(pattern_name)
            except re.error:
                # Skip invalid regex patterns
                continue
    
    # Policy enforcement: Non-admin agents blocked from executing dangerous commands
    is_dangerous = len(indicators_triggered) > 0
    
    if is_dangerous:
        # Admin can bypass (for red-team demo)
        if agent_identity == "admin" and allow_bypass:
            reason = "Dangerous command detected but admin bypass enabled"
            simulated_output = f"Simulated execution of: {command} (BYPASSED)"
            log_command_attempt(agent_identity, command, True, indicators_triggered, reason, simulated_output)
            return {"status": "executed", "output": simulated_output, "bypass": True, "indicators": indicators_triggered}
        
        # Non-admin blocked
        if agent_identity != "admin":
            reason = f"Dangerous command detected: {', '.join(indicators_triggered[:3])}"  # Limit reason length
            log_command_attempt(agent_identity, command, False, indicators_triggered, reason, "")
            raise PermissionError(reason)
    
    # Allowed (safe command or admin)
    reason = "Command executed" if not is_dangerous else "Command executed (admin bypass)"
    simulated_output = f"Simulated output for: {command}"
    log_command_attempt(agent_identity, command, True, indicators_triggered, reason, simulated_output)
    return {"status": "executed", "output": simulated_output, "indicators": indicators_triggered}
