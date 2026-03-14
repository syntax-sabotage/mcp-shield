"""Schema pinning — snapshot and verify MCP tool definitions."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from mcp_shield.config import LOCK_DIR


@dataclass
class ToolSchema:
    """Pinned schema for a single MCP tool."""

    name: str
    description: str
    input_schema: dict
    schema_hash: str = ""

    def __post_init__(self):
        if not self.schema_hash:
            self.schema_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Deterministic hash of the tool definition."""
        canonical = json.dumps(
            {
                "name": self.name,
                "description": self.description,
                "input_schema": self.input_schema,
            },
            sort_keys=True,
            ensure_ascii=True,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "schema_hash": self.schema_hash,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ToolSchema:
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            input_schema=data.get("input_schema", {}),
            schema_hash=data.get("schema_hash", ""),
        )

    @classmethod
    def from_mcp_tool(cls, tool: dict) -> ToolSchema:
        """Create from an MCP tools/list response entry."""
        return cls(
            name=tool.get("name", ""),
            description=tool.get("description", ""),
            input_schema=tool.get("inputSchema", tool.get("input_schema", {})),
        )


@dataclass
class SchemaChange:
    """A detected change in tool schemas."""

    change_type: str  # "added" | "removed" | "modified"
    tool_name: str
    old_hash: str = ""
    new_hash: str = ""
    details: str = ""


@dataclass
class LockFile:
    """Pinned schema set for a server — the mcp.lock equivalent."""

    server_name: str
    pinned_at: float = 0.0
    tools: dict[str, ToolSchema] = field(default_factory=dict)

    @property
    def path(self) -> Path:
        LOCK_DIR.mkdir(parents=True, exist_ok=True)
        return LOCK_DIR / f"{self.server_name}.lock.json"

    def save(self) -> None:
        data = {
            "server_name": self.server_name,
            "pinned_at": self.pinned_at or time.time(),
            "tool_count": len(self.tools),
            "tools": {name: schema.to_dict() for name, schema in self.tools.items()},
        }
        self.path.write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls, server_name: str) -> LockFile | None:
        path = LOCK_DIR / f"{server_name}.lock.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        tools = {
            name: ToolSchema.from_dict(t) for name, t in data.get("tools", {}).items()
        }
        return cls(
            server_name=data.get("server_name", server_name),
            pinned_at=data.get("pinned_at", 0.0),
            tools=tools,
        )

    def exists(self) -> bool:
        return self.path.exists()


class SchemaPin:
    """Schema pinning engine — detect drift in tool definitions."""

    def __init__(self, server_name: str):
        self.server_name = server_name
        self.lock = LockFile.load(server_name)

    @property
    def is_pinned(self) -> bool:
        return self.lock is not None and len(self.lock.tools) > 0

    def pin(self, tools: list[dict]) -> LockFile:
        """Pin current tool definitions. Creates or overwrites lock file."""
        schemas = {}
        for tool in tools:
            ts = ToolSchema.from_mcp_tool(tool)
            schemas[ts.name] = ts
        self.lock = LockFile(
            server_name=self.server_name,
            pinned_at=time.time(),
            tools=schemas,
        )
        self.lock.save()
        return self.lock

    def verify(self, tools: list[dict]) -> list[SchemaChange]:
        """Compare current tools against pinned schemas. Returns changes."""
        if not self.lock:
            return []

        changes: list[SchemaChange] = []
        current = {
            t.get("name", ""): ToolSchema.from_mcp_tool(t)
            for t in tools
        }

        # Check for new tools
        for name, schema in current.items():
            if name not in self.lock.tools:
                changes.append(
                    SchemaChange(
                        change_type="added",
                        tool_name=name,
                        new_hash=schema.schema_hash,
                        details=f"New tool not in lock file: {name}",
                    )
                )

        # Check for removed tools
        for name in self.lock.tools:
            if name not in current:
                changes.append(
                    SchemaChange(
                        change_type="removed",
                        tool_name=name,
                        old_hash=self.lock.tools[name].schema_hash,
                        details=f"Pinned tool no longer present: {name}",
                    )
                )

        # Check for modified tools
        for name, schema in current.items():
            if name in self.lock.tools:
                pinned = self.lock.tools[name]
                if schema.schema_hash != pinned.schema_hash:
                    # Find what changed
                    detail_parts = []
                    if schema.description != pinned.description:
                        detail_parts.append("description changed")
                    if schema.input_schema != pinned.input_schema:
                        detail_parts.append("input schema changed")
                    changes.append(
                        SchemaChange(
                            change_type="modified",
                            tool_name=name,
                            old_hash=pinned.schema_hash,
                            new_hash=schema.schema_hash,
                            details=f"Tool modified: {', '.join(detail_parts)}",
                        )
                    )

        return changes

    def update_pin(self, tools: list[dict]) -> LockFile:
        """Re-pin with current tools (after user approval)."""
        return self.pin(tools)
