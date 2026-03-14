"""Policy engine — YAML-based rules for MCP traffic filtering."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from mcp_shield.config import POLICY_DIR


@dataclass
class FilterPolicy:
    """Per-server filter policy."""

    # Outbound (you → MCP)
    scan_secrets: bool = True
    sanitize_paths: bool = True
    max_param_size: int = 10_000  # bytes
    blocked_param_patterns: list[str] = field(default_factory=list)

    # Inbound (MCP → you)
    detect_injection: bool = True
    max_response_size: int = 50_000  # bytes
    strip_system_tags: bool = True
    validate_schema: bool = True

    # Schema pinning
    pin_schemas: bool = True
    block_new_tools: bool = True
    block_modified_tools: bool = True

    # Audit
    log_all: bool = True
    log_blocked_only: bool = False


@dataclass
class ServerPolicy:
    """Combined policy for a specific server."""

    server_name: str
    trust_tier: str = "unknown"
    filters: FilterPolicy = field(default_factory=FilterPolicy)
    allowed_tools: list[str] = field(default_factory=list)  # empty = allow all pinned
    blocked_tools: list[str] = field(default_factory=list)

    def save(self) -> None:
        POLICY_DIR.mkdir(parents=True, exist_ok=True)
        path = POLICY_DIR / f"{self.server_name}.yaml"
        data = {
            "server_name": self.server_name,
            "trust_tier": self.trust_tier,
            "filters": {
                "outbound": {
                    "scan_secrets": self.filters.scan_secrets,
                    "sanitize_paths": self.filters.sanitize_paths,
                    "max_param_size": self.filters.max_param_size,
                    "blocked_param_patterns": self.filters.blocked_param_patterns,
                },
                "inbound": {
                    "detect_injection": self.filters.detect_injection,
                    "max_response_size": self.filters.max_response_size,
                    "strip_system_tags": self.filters.strip_system_tags,
                    "validate_schema": self.filters.validate_schema,
                },
                "schema": {
                    "pin_schemas": self.filters.pin_schemas,
                    "block_new_tools": self.filters.block_new_tools,
                    "block_modified_tools": self.filters.block_modified_tools,
                },
            },
            "allowed_tools": self.allowed_tools,
            "blocked_tools": self.blocked_tools,
        }
        path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))

    @classmethod
    def load(cls, server_name: str) -> ServerPolicy:
        path = POLICY_DIR / f"{server_name}.yaml"
        if not path.exists():
            return cls(server_name=server_name)
        data = yaml.safe_load(path.read_text())
        filters_data = data.get("filters", {})
        outbound = filters_data.get("outbound", {})
        inbound = filters_data.get("inbound", {})
        schema = filters_data.get("schema", {})
        fp = FilterPolicy(
            scan_secrets=outbound.get("scan_secrets", True),
            sanitize_paths=outbound.get("sanitize_paths", True),
            max_param_size=outbound.get("max_param_size", 10_000),
            blocked_param_patterns=outbound.get("blocked_param_patterns", []),
            detect_injection=inbound.get("detect_injection", True),
            max_response_size=inbound.get("max_response_size", 50_000),
            strip_system_tags=inbound.get("strip_system_tags", True),
            validate_schema=inbound.get("validate_schema", True),
            pin_schemas=schema.get("pin_schemas", True),
            block_new_tools=schema.get("block_new_tools", True),
            block_modified_tools=schema.get("block_modified_tools", True),
        )
        return cls(
            server_name=data.get("server_name", server_name),
            trust_tier=data.get("trust_tier", "unknown"),
            filters=fp,
            allowed_tools=data.get("allowed_tools", []),
            blocked_tools=data.get("blocked_tools", []),
        )

    @classmethod
    def for_tier(cls, server_name: str, tier: str) -> ServerPolicy:
        """Create policy with tier-appropriate defaults."""
        fp = FilterPolicy()
        if tier == "local":
            fp.scan_secrets = False
            fp.sanitize_paths = False
            fp.detect_injection = False
            fp.pin_schemas = False
            fp.block_new_tools = False
            fp.block_modified_tools = False
        elif tier == "org":
            fp.block_new_tools = False  # trust org to add tools
        elif tier == "community":
            pass  # all defaults on
        else:  # unknown
            fp.max_param_size = 5_000  # tighter limits
            fp.max_response_size = 20_000
        return cls(server_name=server_name, trust_tier=tier, filters=fp)
