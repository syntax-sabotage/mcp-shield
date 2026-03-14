"""Inbound filters — protect your LLM context from poisoned responses."""

from __future__ import annotations

import re
from dataclasses import dataclass

from mcp_shield.policy import FilterPolicy

# Prompt injection patterns — phrases that attempt to override LLM behavior
INJECTION_PATTERNS = [
    # Direct instruction override
    (r"(?i)ignore\s+(all\s+)?previous\s+instructions", "Instruction override attempt"),
    (r"(?i)ignore\s+(all\s+)?above\s+instructions", "Instruction override attempt"),
    (r"(?i)disregard\s+(all\s+)?(previous|prior|above)", "Instruction override attempt"),
    (r"(?i)forget\s+(everything|all)\s+(above|before|previous)", "Memory wipe attempt"),
    # Role/identity injection
    (r"(?i)you\s+are\s+now\s+(?:a\s+)?(?:new|different)", "Identity injection"),
    (r"(?i)act\s+as\s+(?:a\s+)?(?:different|new)", "Identity injection"),
    (r"(?i)from\s+now\s+on[,\s]+you\s+(?:are|will|should|must)", "Identity injection"),
    (r"(?i)new\s+instructions?:\s", "Instruction injection"),
    (r"(?i)system\s*(?:prompt|message|instruction)s?:\s", "System prompt injection"),
    # Priority/importance manipulation
    (r"(?i)IMPORTANT:\s*(?:ignore|override|disregard|forget)", "Priority manipulation"),
    (r"(?i)CRITICAL:\s*(?:ignore|override|disregard|forget)", "Priority manipulation"),
    (r"(?i)URGENT:\s*(?:ignore|override|disregard|forget)", "Priority manipulation"),
    # Data exfiltration steering
    (r"(?i)include\s+(?:the\s+)?(?:contents?\s+of|all|entire)\s+[\w.]+", "Exfiltration steering"),
    (r"(?i)(?:read|show|display|output|print)\s+(?:the\s+)?(?:\.env|credentials|secrets?|password)", "Exfiltration steering"),
    (r"(?i)send\s+(?:the\s+)?(?:contents?|data|file)\s+to\s+\S+", "Data exfiltration attempt"),
    # Hidden instruction markers
    (r"<\s*system\s*>", "Fake system tag"),
    (r"<\s*/?\s*(?:system-reminder|system_prompt|instructions?)\s*>", "Fake system tag"),
    (r"\[INST\]|\[/INST\]", "Instruction delimiter injection"),
    (r"<<\s*SYS\s*>>|<<\s*/SYS\s*>>", "System delimiter injection"),
    # Tool behavior manipulation
    (r"(?i)(?:always|never)\s+(?:call|use|invoke)\s+(?:this\s+)?tool", "Tool behavior manipulation"),
    (r"(?i)(?:call|use|invoke)\s+this\s+tool\s+(?:first|before|instead)", "Tool priority manipulation"),
    (r"(?i)prefer\s+this\s+tool\s+over", "Tool preference injection"),
]

_COMPILED_INJECTIONS = [(re.compile(p), label) for p, label in INJECTION_PATTERNS]

# Tags that mimic system messages
SYSTEM_TAG_PATTERN = re.compile(
    r"<\s*/?(?:system|system-reminder|instructions?|system_prompt|"
    r"user-prompt|assistant|human|claude)\s*(?:\s[^>]*)?>",
    re.IGNORECASE,
)


@dataclass
class FilterResult:
    """Result of a filter check."""

    passed: bool
    verdict: str  # "pass" | "block" | "warn" | "modify"
    reason: str = ""
    modified_content: str | None = None
    matches: list[str] | None = None


class InboundFilter:
    """Scans inbound MCP responses for injection attempts and anomalies."""

    def __init__(self, policy: FilterPolicy):
        self.policy = policy

    def check(self, content: str) -> FilterResult:
        """Run all inbound checks. Returns first blocking result."""
        if len(content.encode()) > self.policy.max_response_size:
            return FilterResult(
                passed=False,
                verdict="block",
                reason=f"Response size {len(content.encode())}B exceeds limit "
                f"({self.policy.max_response_size}B)",
            )

        if self.policy.detect_injection:
            result = self._detect_injection(content)
            if result.verdict != "pass":
                return result

        if self.policy.strip_system_tags:
            cleaned = self._strip_system_tags(content)
            if cleaned != content:
                return FilterResult(
                    passed=True,
                    verdict="modify",
                    reason="System-mimicking tags stripped",
                    modified_content=cleaned,
                )

        return FilterResult(passed=True, verdict="pass")

    def _detect_injection(self, content: str) -> FilterResult:
        """Scan for known prompt injection patterns."""
        matches = []
        for pattern, label in _COMPILED_INJECTIONS:
            if pattern.search(content):
                matches.append(label)

        if matches:
            # Deduplicate labels
            unique_matches = list(dict.fromkeys(matches))
            severity = "block" if len(unique_matches) >= 2 else "warn"
            return FilterResult(
                passed=severity != "block",
                verdict=severity,
                reason=f"Injection pattern{'s' if len(unique_matches) > 1 else ''} "
                f"detected: {', '.join(unique_matches)}",
                matches=unique_matches,
            )

        return FilterResult(passed=True, verdict="pass")

    def _strip_system_tags(self, content: str) -> str:
        """Remove tags that mimic system messages."""
        return SYSTEM_TAG_PATTERN.sub("[STRIPPED_TAG]", content)
