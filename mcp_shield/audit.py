"""Audit logger — JSONL event log for all MCP traffic decisions."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from mcp_shield.config import AUDIT_FILE


@dataclass
class AuditEvent:
    """Single audit log entry."""

    timestamp: float
    server: str
    direction: str  # "outbound" | "inbound"
    method: str  # JSON-RPC method
    tool: str  # tool name (if applicable)
    verdict: str  # "pass" | "block" | "warn" | "modify"
    reason: str  # why blocked/warned
    details: dict | None = None  # extra context

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


class AuditLog:
    """Append-only JSONL audit log."""

    def __init__(self, path: Path | None = None):
        self.path = path or AUDIT_FILE
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        server: str,
        direction: str,
        method: str,
        tool: str = "",
        verdict: str = "pass",
        reason: str = "",
        details: dict | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            timestamp=time.time(),
            server=server,
            direction=direction,
            method=method,
            tool=tool,
            verdict=verdict,
            reason=reason,
            details=details,
        )
        with open(self.path, "a") as f:
            f.write(event.to_json() + "\n")
        return event

    def read(self, tail: int = 0) -> list[AuditEvent]:
        if not self.path.exists():
            return []
        lines = self.path.read_text().strip().split("\n")
        if tail > 0:
            lines = lines[-tail:]
        events = []
        for line in lines:
            if line.strip():
                data = json.loads(line)
                events.append(AuditEvent(**data))
        return events

    def clear(self) -> None:
        if self.path.exists():
            self.path.write_text("")
