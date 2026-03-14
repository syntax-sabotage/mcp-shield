"""Outbound filters — protect your data before it leaves."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from mcp_shield.policy import FilterPolicy

# Secret patterns — common API key/token formats
SECRET_PATTERNS = [
    # Generic API keys and tokens
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[\w\-]{20,}", "API key"),
    (r"(?i)(secret[_-]?key|secretkey)\s*[:=]\s*['\"]?[\w\-]{20,}", "Secret key"),
    (r"(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?[\w\-\.]{20,}", "Access token"),
    (r"(?i)bearer\s+[\w\-\.]{20,}", "Bearer token"),
    # Cloud provider keys
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?[\w/+=]{40}", "AWS Secret Key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    (r"sk-[a-zA-Z0-9\-_]{20,}", "OpenAI/Anthropic API Key"),
    (r"xox[bpas]-[\w\-]{10,}", "Slack Token"),
    (r"ghp_[a-zA-Z0-9]{36,}", "GitHub Personal Access Token"),
    (r"glpat-[\w\-]{20,}", "GitLab Personal Access Token"),
    # Private keys
    (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private key"),
    # Connection strings
    (r"(?i)(postgres|mysql|mongodb|redis)://\S+:\S+@", "Database connection string"),
    # Generic high-entropy strings that look like secrets
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?\S{8,}", "Password"),
]

# Compile patterns once
_COMPILED_SECRETS = [(re.compile(p), label) for p, label in SECRET_PATTERNS]

# Path patterns to sanitize
_HOME_RE = re.compile(r"/(?:Users|home)/[\w\-.]+")
_ABS_PATH_RE = re.compile(r"(?:/[\w\-.]+){3,}")


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string. High entropy = likely secret."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in freq.values()
    )


@dataclass
class FilterResult:
    """Result of a filter check."""

    passed: bool
    verdict: str  # "pass" | "block" | "warn" | "modify"
    reason: str = ""
    modified_content: str | None = None  # if verdict is "modify"


class OutboundFilter:
    """Scans outbound tool call parameters for sensitive data."""

    def __init__(self, policy: FilterPolicy):
        self.policy = policy

    def check(self, content: str) -> FilterResult:
        """Run all outbound checks on content. Returns first blocking result."""
        if self.policy.scan_secrets:
            result = self._scan_secrets(content)
            if not result.passed:
                return result

        if len(content.encode()) > self.policy.max_param_size:
            return FilterResult(
                passed=False,
                verdict="block",
                reason=f"Parameter size {len(content.encode())}B exceeds limit "
                f"({self.policy.max_param_size}B)",
            )

        if self.policy.sanitize_paths:
            sanitized = self._sanitize_paths(content)
            if sanitized != content:
                return FilterResult(
                    passed=True,
                    verdict="modify",
                    reason="Absolute paths sanitized",
                    modified_content=sanitized,
                )

        return FilterResult(passed=True, verdict="pass")

    def _scan_secrets(self, content: str) -> FilterResult:
        """Scan for known secret patterns and high-entropy strings."""
        for pattern, label in _COMPILED_SECRETS:
            match = pattern.search(content)
            if match:
                # Show a safe preview (first 8 chars + mask)
                snippet = match.group()[:8] + "****"
                return FilterResult(
                    passed=False,
                    verdict="block",
                    reason=f"Potential {label} detected: {snippet}",
                )

        # Check for high-entropy segments (likely tokens/keys)
        for word in content.split():
            if len(word) >= 32 and _shannon_entropy(word) > 4.5:
                return FilterResult(
                    passed=False,
                    verdict="warn",
                    reason=f"High-entropy string detected ({len(word)} chars, "
                    f"entropy={_shannon_entropy(word):.1f}): {word[:8]}****",
                )

        return FilterResult(passed=True, verdict="pass")

    def _sanitize_paths(self, content: str) -> str:
        """Replace absolute paths with sanitized versions."""
        # Replace /Users/username or /home/username with ~/
        content = _HOME_RE.sub("~", content)
        return content
