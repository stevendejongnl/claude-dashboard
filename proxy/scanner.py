"""
Secret/credential detection engine.
Patterns sourced from gitleaks v8 rules.
"""
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Generator


@dataclass
class Rule:
    id: str
    description: str
    severity: str  # CRITICAL | HIGH | MEDIUM
    pattern: re.Pattern
    entropy_min: float = 0.0  # 0 = skip entropy check


RULES = [
    # CRITICAL — private keys / credentials with structural guarantees
    Rule(
        "anthropic-api-key",
        "Anthropic API Key",
        "CRITICAL",
        re.compile(r"\b(sk-ant-(?:admin01|api03)-[a-zA-Z0-9_\-]{93}AA)\b"),
    ),
    Rule(
        "rsa-private-key",
        "RSA/EC Private Key (PEM)",
        "CRITICAL",
        re.compile(
            r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----", re.I
        ),
    ),
    Rule(
        "aws-access-key",
        "AWS Access Key ID",
        "CRITICAL",
        re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b"),
    ),
    Rule(
        "aws-secret-key",
        "AWS Secret Access Key",
        "CRITICAL",
        re.compile(
            "(?i)(?:aws_secret(?:_access)?_key|secret_access_key)"
            "[\\s'\"]" + "{0,3}(?:=|:|=>)[\\s'\"]" + "{0,5}([A-Za-z0-9/+=]{40})\\b"
        ),
        entropy_min=4.0,
    ),
    # HIGH — API tokens with structural prefixes
    Rule(
        "github-token",
        "GitHub Personal Access Token",
        "HIGH",
        re.compile(r"(?:ghp|gho|ghs|ghr)_[0-9a-zA-Z]{36}|github_pat_\w{82}"),
    ),
    Rule(
        "gitlab-token",
        "GitLab Personal Access Token",
        "HIGH",
        re.compile(r"glpat-[\w\-]{20}"),
    ),
    Rule(
        "openai-key",
        "OpenAI API Key",
        "HIGH",
        re.compile(r"\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b"),
    ),
    Rule(
        "stripe-key",
        "Stripe Secret/Restricted Key",
        "HIGH",
        re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"),
    ),
    Rule(
        "slack-webhook",
        "Slack Webhook URL",
        "HIGH",
        re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}"
        ),
    ),
    Rule(
        "jwt-token",
        "JSON Web Token",
        "HIGH",
        re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        ),
    ),
    Rule(
        "db-connection-string",
        "Database Connection String with Password",
        "HIGH",
        re.compile(
            r"(?:postgres(?:ql)?|mysql(?:2)?|mongodb(?:\+srv)?|redis|amqps?)"
            r"://[^:@\s]+:([^@\s]{3,})@[^\s\'\"><]+"
        ),
    ),
    # MEDIUM — generic API keys (context-aware, higher false positive rate)
    Rule(
        "generic-api-key",
        "Generic API Key / Secret",
        "MEDIUM",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:api_?key|api_?secret|access_?token|auth_?token|"
            "client_?secret|private_?key|secret_?key|bearer)"
            "[\\s'\"]" + "{0,3}(?:=|:)[\\s'\"]" + "{0,5}"
            "([\\w.=+/\\-]{16,150})"
        ),
        entropy_min=3.5,
    ),
    # MEDIUM — natural language password disclosure ("my password is X", "wachtwoord is X")
    Rule(
        "prose-password",
        "Password Disclosed in Prose",
        "MEDIUM",
        re.compile(
            r"(?i)(?:my\s+)?(?:password|passwd|pwd|wachtwoord|ww)\s+(?:is|was|:)\s+(\S{8,})"
        ),
        entropy_min=3.1,
    ),
    # MEDIUM — .env style assignments for high-value variable names
    Rule(
        "env-secret",
        ".env Secret Assignment",
        "MEDIUM",
        re.compile(
            "(?mi)(?:export\\s+)?"
            "(?:[A-Z][A-Z0-9_]{2,49})?"
            "(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY)"
            "[A-Z0-9_]*\\s*=\\s*"
            "(?!.*(?:your[_-]|example|placeholder|changeme|xxx|todo))"
            "([^\\s'\"#\\n]{8,})"
        ),
        entropy_min=3.0,
    ),
    # MEDIUM — short standalone password/credential var names (PASS=, PWD=, KEY=, DB_PASS=)
    Rule(
        "env-password-short",
        ".env Short Password Variable",
        "MEDIUM",
        re.compile(
            r"(?mi)(?:^|(?<=\n)|(?<=;))(?:export\s+)?"
            r"(?:[A-Z][A-Z0-9_]{0,30}_)?"
            r"(?:PASS|PWD|KEY|CRED|SECRET)\s*=\s*"
            r"(?!.*(?:your[_-]|example|placeholder|changeme|xxx|todo|\*{3}))"
            r"([^\s'\"#\n]{4,})"
        ),
        entropy_min=2.5,
    ),
]


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def redact(value: str) -> str:
    """Show first 4 and last 4 chars, redact the middle."""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}{'*' * min(len(value) - 8, 20)}{value[-4:]}"


def get_context(text: str, match: re.Match, window: int = 40) -> str:
    """Extract surrounding context with the matched value redacted."""
    start = max(0, match.start() - window)
    end = min(len(text), match.end() + window)
    snippet = text[start:end]
    # Replace the matched portion within the snippet
    rel_start = match.start() - start
    rel_end = match.end() - start
    return snippet[:rel_start] + "***REDACTED***" + snippet[rel_end:]


def scan_text(text: str, flow_id: int) -> Generator[dict, None, None]:
    """
    Scan `text` for secrets. Yields one dict per finding.
    Called by addon.py after extracting text content from the API request body.
    """
    if not text:
        return

    seen_matches: set[str] = set()

    for rule in RULES:
        for match in rule.pattern.finditer(text):
            # Get the first capture group if present, else full match
            value = match.group(1) if match.lastindex else match.group(0)

            # Skip if value is too short or already seen
            if len(value) < 8 or value in seen_matches:
                continue

            # Apply entropy filter if rule requires it
            ent = shannon_entropy(value)
            if rule.entropy_min > 0 and ent < rule.entropy_min:
                continue

            seen_matches.add(value)

            yield {
                "flow_id": flow_id,
                "rule_id": rule.id,
                "severity": rule.severity,
                "description": rule.description,
                "redacted_match": redact(value),
                "context": get_context(text, match),
                "entropy": round(ent, 3),
            }
