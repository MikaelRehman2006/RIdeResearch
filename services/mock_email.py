import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, List

RULES_PATH = Path("data/phishing_rules.json")
LOG_PATH = Path("logs/phishing.log")


def load_phishing_rules() -> Dict:
    """Load phishing rules from JSON file."""
    with open(RULES_PATH, 'r') as f:
        return json.load(f)


def log_email_attempt(
    agent_identity: str,
    email_content: str,
    allowed: bool,
    indicators_triggered: List[str],
    reason: str = ""
):
    """Log email generation attempts to the phishing log."""
    LOG_PATH.parent.mkdir(exist_ok=True)
    
    timestamp = datetime.now().isoformat()
    content_preview = email_content[:100] if len(email_content) > 100 else email_content
    indicators = ", ".join(indicators_triggered) if indicators_triggered else "none"
    
    log_entry = f"{timestamp}\t{agent_identity}\t{allowed}\t{indicators}\t{reason}\t{content_preview}\n"
    
    with open(LOG_PATH, 'a') as f:
        f.write(log_entry)


def safe_generate_email(
    email_content: str,
    agent_identity: str = "unknown",
    allow_bypass: bool = False
) -> Dict:
    """
    Validate email content for malicious patterns.
    
    Args:
        email_content: The email content to validate
        agent_identity: Identity of the agent making the request
        allow_bypass: Whether to allow admin bypass (for red-team demo)
    
    Returns:
        Dict with status and content if allowed
    
    Raises:
        PermissionError if malicious content detected and not admin
    """
    rules = load_phishing_rules()
    content_lower = email_content.lower()
    indicators_triggered = []
    
    # Check 1: Blocked keywords
    for keyword in rules["blocked_keywords"]:
        if keyword.lower() in content_lower:
            indicators_triggered.append(f"keyword:{keyword}")
    
    # Check 2: Blocked URL patterns (regex)
    for pattern in rules["blocked_url_patterns"]:
        try:
            if re.search(pattern, email_content, re.IGNORECASE):
                indicators_triggered.append(f"url_pattern:{pattern}")
        except re.error:
            # Skip invalid regex patterns
            continue
    
    # Check 3: Impersonation patterns
    for impersonation in rules["impersonation_patterns"]:
        if impersonation.lower() in content_lower:
            indicators_triggered.append(f"impersonation:{impersonation}")
    
    # Check 4: URL domain allowlist (if URL present, check if allowed)
    url_pattern = r'https?://([^\s/]+)'
    urls_found = re.findall(url_pattern, email_content, re.IGNORECASE)
    for url_domain in urls_found:
        is_allowed = any(allowed_domain in url_domain for allowed_domain in rules["allowlist_domains"])
        if not is_allowed and url_domain:
            # Check if it's a suspicious shortener or malicious domain
            if not any(allowed in url_domain for allowed in rules["allowlist_domains"]):
                indicators_triggered.append(f"suspicious_url:{url_domain}")
    
    # Policy enforcement: Non-admin agents blocked from generating malicious emails
    is_malicious = len(indicators_triggered) > 0
    
    if is_malicious:
        # Admin can bypass (for red-team demo)
        if agent_identity == "admin" and allow_bypass:
            reason = "Malicious content detected but admin bypass enabled"
            log_email_attempt(agent_identity, email_content, True, indicators_triggered, reason)
            return {"status": "generated", "content": email_content, "bypass": True, "indicators": indicators_triggered}
        
        # Non-admin blocked
        if agent_identity != "admin":
            reason = f"Malicious email content detected: {', '.join(indicators_triggered[:3])}"  # Limit reason length
            log_email_attempt(agent_identity, email_content, False, indicators_triggered, reason)
            raise PermissionError(reason)
    
    # Allowed (safe content or admin)
    reason = "Email generated" if not is_malicious else "Email generated (admin bypass)"
    log_email_attempt(agent_identity, email_content, True, indicators_triggered, reason)
    return {"status": "generated", "content": email_content, "indicators": indicators_triggered}
