"""Configuration management for MCP Shield."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

SHIELD_DIR = Path.home() / ".mcp-shield"
SERVERS_FILE = SHIELD_DIR / "servers.json"
AUDIT_FILE = SHIELD_DIR / "audit.jsonl"
LOCK_DIR = SHIELD_DIR / "locks"
POLICY_DIR = SHIELD_DIR / "policies"

DEFAULT_PROXY_HOST = "127.0.0.1"
DEFAULT_PROXY_PORT = 9800


@dataclass
class ServerConfig:
    """Configuration for a registered MCP server."""

    name: str
    url: str
    trust_tier: str = "unknown"  # local, org, community, unknown
    enabled: bool = True
    proxy_port: int = 0  # 0 = auto-assign from base port

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "url": self.url,
            "trust_tier": self.trust_tier,
            "enabled": self.enabled,
            "proxy_port": self.proxy_port,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ServerConfig:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ShieldConfig:
    """Global MCP Shield configuration."""

    servers: dict[str, ServerConfig] = field(default_factory=dict)
    proxy_host: str = DEFAULT_PROXY_HOST
    base_port: int = DEFAULT_PROXY_PORT

    def save(self) -> None:
        SHIELD_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "proxy_host": self.proxy_host,
            "base_port": self.base_port,
            "servers": {k: v.to_dict() for k, v in self.servers.items()},
        }
        SERVERS_FILE.write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls) -> ShieldConfig:
        if not SERVERS_FILE.exists():
            return cls()
        data = json.loads(SERVERS_FILE.read_text())
        servers = {
            k: ServerConfig.from_dict(v) for k, v in data.get("servers", {}).items()
        }
        return cls(
            servers=servers,
            proxy_host=data.get("proxy_host", DEFAULT_PROXY_HOST),
            base_port=data.get("base_port", DEFAULT_PROXY_PORT),
        )

    def next_port(self) -> int:
        used = {s.proxy_port for s in self.servers.values() if s.proxy_port}
        port = self.base_port
        while port in used:
            port += 1
        return port
