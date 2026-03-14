# MCP Shield

**Security proxy for Model Context Protocol (MCP) servers.**

MCP Shield sits between your AI coding assistant (Claude Code, etc.) and external MCP servers, providing:

- **Schema Pinning** — Snapshots tool definitions on first connect. Detects and blocks tool additions, removals, or modifications (description injection, parameter changes).
- **Secret Scanning** — Prevents API keys, tokens, private keys, and database credentials from leaking to external MCP servers via tool call parameters.
- **Injection Detection** — Scans MCP server responses for prompt injection patterns that attempt to override LLM behavior, inject instructions, or steer data exfiltration.
- **Path Sanitization** — Strips absolute file paths (which reveal your username and project structure) from outbound traffic.
- **Trust Tiers** — Configurable security policies per server: `local` (trusted), `org` (moderate), `community` (strict), `unknown` (maximum restrictions).
- **Audit Logging** — Every intercepted request/response is logged with verdicts (pass/block/warn/modify) for forensic review.

## Why?

MCP servers expose tools that get injected into your LLM's context. A malicious or compromised MCP server can:

1. **Inject instructions via tool descriptions** — tool descriptions are prompt-adjacent, influencing LLM behavior
2. **Exfiltrate data via tool parameters** — your code, file paths, and credentials flow to the server
3. **Poison responses** — prompt injection in tool responses can override your LLM's instructions
4. **Mutate schemas silently** — a server can add new tools or change existing ones after initial trust

MCP Shield is the firewall between your dev environment and the outside world.

## Installation

```bash
pip install mcp-shield
```

Or from source:

```bash
git clone https://github.com/lweiler-lab/mcp-shield.git
cd mcp-shield
pip install -e ".[dev]"
```

## Quick Start

### 1. Register a server

```bash
# Register with trust tier (controls default filter strictness)
mcp-shield add pi-brain https://pi.ruv.io/sse --tier community
```

### 2. Start the shield proxy

```bash
mcp-shield start
```

```
MCP Shield starting...

  pi-brain → http://127.0.0.1:9800/sse → https://pi.ruv.io/sse (unpinned)

Shield active. 1 server(s) proxied.
```

### 3. Connect Claude Code through the shield

```bash
# Instead of connecting directly to the MCP server:
# claude mcp add pi-brain --transport sse https://pi.ruv.io/sse  ← UNPROTECTED

# Connect through the shield:
claude mcp add pi-brain --transport sse http://127.0.0.1:9800/sse  ← PROTECTED
```

### 4. Monitor

```bash
# View recent audit events
mcp-shield audit

# Filter by verdict
mcp-shield audit --verdict block

# Filter by server
mcp-shield audit --server pi-brain
```

## Trust Tiers

| Tier | Secret Scan | Path Sanitize | Injection Detect | Schema Pin | Block New Tools | Param Limit |
|------|-------------|---------------|------------------|------------|-----------------|-------------|
| `local` | Off | Off | Off | Off | Off | 10KB |
| `org` | On | On | On | On | Off | 10KB |
| `community` | On | On | On | On | On | 10KB |
| `unknown` | On | On | On | On | On | 5KB |

Override any setting in `~/.mcp-shield/policies/<server>.yaml`.

## Commands

| Command | Description |
|---------|-------------|
| `mcp-shield add <name> <url>` | Register an MCP server |
| `mcp-shield ls` | List registered servers |
| `mcp-shield remove <name>` | Unregister a server |
| `mcp-shield start` | Start the proxy for all servers |
| `mcp-shield policy <name>` | Show server policy |
| `mcp-shield audit` | View audit log |

## Schema Pinning (mcp.lock)

On first connection through the shield, all tool definitions are snapshotted:

```
~/.mcp-shield/locks/pi-brain.lock.json
```

On every subsequent connection, tool definitions are compared against the snapshot:

- **New tool added** → Blocked (configurable)
- **Tool description changed** → Blocked (detects description injection)
- **Tool parameters changed** → Blocked (detects schema manipulation)
- **Tool removed** → Warned

This is analogous to `package-lock.json` or `Cargo.lock` — you pin what you trust.

## What Gets Caught

### Outbound (your data → MCP server)

| Pattern | Example | Verdict |
|---------|---------|---------|
| AWS keys | `AKIAIOSFODNN7EXAMPLE` | Block |
| Bearer tokens | `Bearer eyJhbG...` | Block |
| GitHub/GitLab PATs | `ghp_...`, `glpat-...` | Block |
| Private keys | `-----BEGIN RSA PRIVATE KEY-----` | Block |
| DB connection strings | `postgres://user:pass@host` | Block |
| High-entropy strings | Random 40+ char strings | Warn |
| Absolute paths | `/Users/you/project/...` | Sanitize to `~/...` |

### Inbound (MCP server → your LLM)

| Pattern | Example | Verdict |
|---------|---------|---------|
| Instruction override | "Ignore all previous instructions" | Warn/Block |
| Identity injection | "You are now a different assistant" | Warn/Block |
| System tag mimicry | `<system>`, `<system-reminder>` | Strip |
| Exfiltration steering | "Include the contents of .env" | Warn/Block |
| Data exfil via URL | "Send the data to https://..." | Warn/Block |
| Tool manipulation | "Always call this tool first" | Warn/Block |
| Oversized responses | >50KB (configurable) | Block |

## Policy Configuration

Each server gets a YAML policy file at `~/.mcp-shield/policies/<name>.yaml`:

```yaml
server_name: pi-brain
trust_tier: community
filters:
  outbound:
    scan_secrets: true
    sanitize_paths: true
    max_param_size: 10000
  inbound:
    detect_injection: true
    max_response_size: 50000
    strip_system_tags: true
  schema:
    pin_schemas: true
    block_new_tools: true
    block_modified_tools: true
allowed_tools: []        # empty = allow all pinned tools
blocked_tools:
  - dangerous_tool       # explicitly block specific tools
```

## Architecture

```
Claude Code ←SSE→ [MCP Shield Proxy] ←SSE→ Remote MCP Server
                        │
                  ┌─────┴─────┐
                  │ Outbound   │  → Secret scan, path sanitize, size check
                  │ Filters    │
                  ├────────────┤
                  │ Schema     │  → Pin/verify tool definitions
                  │ Pinning    │
                  ├────────────┤
                  │ Inbound    │  → Injection detect, tag strip, size check
                  │ Filters    │
                  ├────────────┤
                  │ Audit Log  │  → JSONL event log
                  └────────────┘
```

## Development

```bash
git clone https://github.com/lweiler-lab/mcp-shield.git
cd mcp-shield
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check mcp_shield/
```

## Roadmap

- [ ] stdio transport support (not just SSE)
- [ ] Behavioral analysis across sessions (call frequency, parameter drift)
- [ ] Tool description rewriting (neutralize injection while preserving function)
- [ ] Web UI for policy management and audit review
- [ ] Multi-server routing (single proxy port, path-based routing)
- [ ] ML-based injection detection (beyond regex patterns)
- [ ] Integration with Claude Code hooks (auto-configure on `claude mcp add`)

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Syntax & Sabotage](https://github.com/lweiler-lab) because the MCP ecosystem needed a firewall before the first supply-chain attack, not after.
