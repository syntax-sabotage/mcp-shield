"""Tests for configuration and policy management."""

import json
import tempfile
from pathlib import Path

from mcp_shield.config import ServerConfig, ShieldConfig
from mcp_shield.policy import FilterPolicy, ServerPolicy


class TestServerConfig:
    def test_roundtrip(self):
        sc = ServerConfig(name="test", url="https://example.com/sse", trust_tier="community")
        data = sc.to_dict()
        sc2 = ServerConfig.from_dict(data)
        assert sc.name == sc2.name
        assert sc.url == sc2.url
        assert sc.trust_tier == sc2.trust_tier


class TestShieldConfig:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        import mcp_shield.config as cfg
        self._orig_dir = cfg.SHIELD_DIR
        self._orig_file = cfg.SERVERS_FILE
        cfg.SHIELD_DIR = Path(self.tmpdir)
        cfg.SERVERS_FILE = Path(self.tmpdir) / "servers.json"

    def teardown_method(self):
        import mcp_shield.config as cfg
        cfg.SHIELD_DIR = self._orig_dir
        cfg.SERVERS_FILE = self._orig_file

    def test_save_and_load(self):
        config = ShieldConfig()
        config.servers["test"] = ServerConfig(
            name="test", url="https://example.com/sse", proxy_port=9800
        )
        config.save()

        loaded = ShieldConfig.load()
        assert "test" in loaded.servers
        assert loaded.servers["test"].url == "https://example.com/sse"

    def test_next_port(self):
        config = ShieldConfig(base_port=9800)
        assert config.next_port() == 9800

        config.servers["a"] = ServerConfig(name="a", url="", proxy_port=9800)
        assert config.next_port() == 9801

        config.servers["b"] = ServerConfig(name="b", url="", proxy_port=9801)
        assert config.next_port() == 9802


class TestServerPolicy:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        import mcp_shield.policy as pol
        self._orig_dir = pol.POLICY_DIR
        pol.POLICY_DIR = Path(self.tmpdir)

    def teardown_method(self):
        import mcp_shield.policy as pol
        pol.POLICY_DIR = self._orig_dir

    def test_tier_defaults_local(self):
        p = ServerPolicy.for_tier("local-svc", "local")
        assert not p.filters.scan_secrets  # trusted
        assert not p.filters.pin_schemas

    def test_tier_defaults_unknown(self):
        p = ServerPolicy.for_tier("sketchy", "unknown")
        assert p.filters.scan_secrets
        assert p.filters.pin_schemas
        assert p.filters.max_param_size == 5_000  # tighter

    def test_tier_defaults_community(self):
        p = ServerPolicy.for_tier("oss", "community")
        assert p.filters.scan_secrets
        assert p.filters.block_new_tools

    def test_save_and_load(self):
        p = ServerPolicy.for_tier("test", "community")
        p.blocked_tools = ["evil_tool"]
        p.save()

        loaded = ServerPolicy.load("test")
        assert loaded.trust_tier == "community"
        assert loaded.filters.scan_secrets
        assert "evil_tool" in loaded.blocked_tools
