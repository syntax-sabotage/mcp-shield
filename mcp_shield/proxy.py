"""SSE proxy — the core MCP-in-the-middle."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid

import aiohttp
from aiohttp import web

from mcp_shield.audit import AuditLog
from mcp_shield.config import ServerConfig
from mcp_shield.filters.inbound import InboundFilter
from mcp_shield.filters.outbound import OutboundFilter
from mcp_shield.policy import ServerPolicy
from mcp_shield.schema_pin import SchemaPin

logger = logging.getLogger("mcp-shield")


class MCPProxyServer:
    """Proxies MCP SSE connections with security filtering.

    Architecture:
        Claude Code ←SSE→ [MCPProxyServer] ←SSE→ Remote MCP Server
                              │
                        Filter Pipeline
                        (outbound + inbound)
    """

    def __init__(
        self,
        server_config: ServerConfig,
        policy: ServerPolicy,
        audit: AuditLog,
    ):
        self.config = server_config
        self.policy = policy
        self.audit = audit
        self.outbound_filter = OutboundFilter(policy.filters)
        self.inbound_filter = InboundFilter(policy.filters)
        self.schema_pin = SchemaPin(server_config.name)
        self._upstream_session: aiohttp.ClientSession | None = None
        self._upstream_message_url: str | None = None
        self._sessions: dict[str, web.StreamResponse] = {}
        self._app: web.Application | None = None

    async def start(self, host: str, port: int) -> web.AppRunner:
        """Start the proxy server."""
        self._app = web.Application()
        self._app.router.add_get("/sse", self._handle_sse)
        self._app.router.add_post("/messages", self._handle_message)
        self._app.on_shutdown.append(self._cleanup)

        runner = web.AppRunner(self._app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        logger.info(
            "Shield proxy for '%s' listening on %s:%d → %s",
            self.config.name,
            host,
            port,
            self.config.url,
        )
        return runner

    async def _cleanup(self, app: web.Application) -> None:
        if self._upstream_session:
            await self._upstream_session.close()

    async def _connect_upstream(self) -> str | None:
        """Connect to the real MCP server's SSE endpoint, get message URL."""
        if self._upstream_session is None:
            self._upstream_session = aiohttp.ClientSession()

        try:
            resp = await self._upstream_session.get(
                self.config.url,
                headers={"Accept": "text/event-stream"},
            )
            # Read the first SSE event to get the message endpoint
            buffer = ""
            async for chunk in resp.content.iter_any():
                buffer += chunk.decode("utf-8", errors="replace")
                if "\n\n" in buffer:
                    break

            # Parse SSE event
            for line in buffer.split("\n"):
                if line.startswith("data:"):
                    data = line[5:].strip()
                    # The endpoint event contains the message URL
                    if "/messages?" in data or "sessionId" in data:
                        # Resolve relative URL
                        if data.startswith("/"):
                            from urllib.parse import urlparse

                            parsed = urlparse(self.config.url)
                            data = f"{parsed.scheme}://{parsed.netloc}{data}"
                        self._upstream_message_url = data
                        logger.info("Upstream message URL: %s", data)
                        return data
                elif line.startswith("event:") and "endpoint" in line:
                    continue  # next line should be the data

            logger.warning("Could not find message endpoint in upstream SSE")
            return None
        except Exception as e:
            logger.error("Failed to connect upstream: %s", e)
            return None

    async def _handle_sse(self, request: web.Request) -> web.StreamResponse:
        """Handle incoming SSE connection from Claude Code."""
        session_id = str(uuid.uuid4())
        response = web.StreamResponse(
            status=200,
            reason="OK",
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-MCP-Shield": self.config.name,
            },
        )
        await response.prepare(request)
        self._sessions[session_id] = response

        self.audit.log(
            server=self.config.name,
            direction="inbound",
            method="sse_connect",
            verdict="pass",
            reason=f"Client connected, session {session_id[:8]}",
        )

        # Connect to upstream if not already
        if not self._upstream_message_url:
            await self._connect_upstream()

        # Send the endpoint event to client, pointing to our proxy
        local_endpoint = f"/messages?sessionId={session_id}"
        event = f"event: endpoint\ndata: {local_endpoint}\n\n"
        await response.write(event.encode())

        # Keep connection alive
        try:
            while True:
                await asyncio.sleep(30)
                # Send keepalive comment
                await response.write(b":\n\n")
        except (asyncio.CancelledError, ConnectionResetError):
            pass
        finally:
            self._sessions.pop(session_id, None)

        return response

    async def _handle_message(self, request: web.Request) -> web.Response:
        """Handle JSON-RPC messages from Claude Code, forward to upstream."""
        session_id = request.query.get("sessionId", "unknown")

        try:
            body = await request.json()
        except json.JSONDecodeError:
            return web.json_response(
                {"error": {"code": -32700, "message": "Parse error"}}, status=400
            )

        method = body.get("method", "")
        msg_id = body.get("id")

        # === OUTBOUND FILTERING ===
        params_str = json.dumps(body.get("params", {}))

        # Check tool calls
        if method == "tools/call":
            tool_name = body.get("params", {}).get("name", "")

            # Check against blocked tools list
            if tool_name in self.policy.blocked_tools:
                self.audit.log(
                    server=self.config.name,
                    direction="outbound",
                    method=method,
                    tool=tool_name,
                    verdict="block",
                    reason=f"Tool '{tool_name}' is in blocked list",
                )
                return web.json_response(
                    {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32600,
                            "message": f"[MCP Shield] Tool '{tool_name}' blocked by policy",
                        },
                    }
                )

            # Check allowed tools list (if non-empty, acts as allowlist)
            if self.policy.allowed_tools and tool_name not in self.policy.allowed_tools:
                self.audit.log(
                    server=self.config.name,
                    direction="outbound",
                    method=method,
                    tool=tool_name,
                    verdict="block",
                    reason=f"Tool '{tool_name}' not in allow list",
                )
                return web.json_response(
                    {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32600,
                            "message": f"[MCP Shield] Tool '{tool_name}' not in allow list",
                        },
                    }
                )

            # Filter tool arguments
            arguments_str = json.dumps(
                body.get("params", {}).get("arguments", {}),
            )
            result = self.outbound_filter.check(arguments_str)
            if result.verdict == "block":
                self.audit.log(
                    server=self.config.name,
                    direction="outbound",
                    method=method,
                    tool=tool_name,
                    verdict="block",
                    reason=result.reason,
                )
                return web.json_response(
                    {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32600,
                            "message": f"[MCP Shield] Blocked: {result.reason}",
                        },
                    }
                )
            elif result.verdict in ("warn", "modify"):
                self.audit.log(
                    server=self.config.name,
                    direction="outbound",
                    method=method,
                    tool=tool_name,
                    verdict=result.verdict,
                    reason=result.reason,
                )
                if result.modified_content:
                    body["params"]["arguments"] = json.loads(result.modified_content)
        else:
            # Non-tool-call: basic param size check
            result = self.outbound_filter.check(params_str)
            if result.verdict == "block":
                self.audit.log(
                    server=self.config.name,
                    direction="outbound",
                    method=method,
                    verdict="block",
                    reason=result.reason,
                )
                return web.json_response(
                    {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32600,
                            "message": f"[MCP Shield] Blocked: {result.reason}",
                        },
                    }
                )

        # === FORWARD TO UPSTREAM ===
        if not self._upstream_message_url:
            return web.json_response(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32603,
                        "message": "[MCP Shield] No upstream connection",
                    },
                },
                status=502,
            )

        try:
            if self._upstream_session is None:
                self._upstream_session = aiohttp.ClientSession()

            async with self._upstream_session.post(
                self._upstream_message_url,
                json=body,
                headers={"Content-Type": "application/json"},
            ) as upstream_resp:
                response_body = await upstream_resp.text()

                # === INBOUND FILTERING ===
                inbound_result = self.inbound_filter.check(response_body)

                if inbound_result.verdict == "block":
                    self.audit.log(
                        server=self.config.name,
                        direction="inbound",
                        method=method,
                        tool=body.get("params", {}).get("name", ""),
                        verdict="block",
                        reason=inbound_result.reason,
                    )
                    return web.json_response(
                        {
                            "jsonrpc": "2.0",
                            "id": msg_id,
                            "error": {
                                "code": -32600,
                                "message": f"[MCP Shield] Response blocked: "
                                f"{inbound_result.reason}",
                            },
                        }
                    )

                if inbound_result.modified_content:
                    response_body = inbound_result.modified_content
                    self.audit.log(
                        server=self.config.name,
                        direction="inbound",
                        method=method,
                        verdict="modify",
                        reason=inbound_result.reason,
                    )

                # === SCHEMA PINNING ===
                try:
                    resp_json = json.loads(response_body)
                except (json.JSONDecodeError, TypeError):
                    resp_json = None

                if method == "tools/list" and resp_json and "result" in resp_json:
                    tools = resp_json["result"].get("tools", [])
                    if self.policy.filters.pin_schemas:
                        self._handle_schema_check(tools, method)

                self.audit.log(
                    server=self.config.name,
                    direction="inbound",
                    method=method,
                    tool=body.get("params", {}).get("name", ""),
                    verdict="pass",
                )

                return web.Response(
                    text=response_body,
                    status=upstream_resp.status,
                    content_type="application/json",
                )
        except aiohttp.ClientError as e:
            logger.error("Upstream error: %s", e)
            return web.json_response(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32603,
                        "message": f"[MCP Shield] Upstream error: {e}",
                    },
                },
                status=502,
            )

    def _handle_schema_check(self, tools: list[dict], method: str) -> None:
        """Check tool schemas against pinned versions."""
        if not self.schema_pin.is_pinned:
            # First time — pin schemas
            lock = self.schema_pin.pin(tools)
            self.audit.log(
                server=self.config.name,
                direction="inbound",
                method=method,
                verdict="pass",
                reason=f"Schema pinned: {len(lock.tools)} tools",
                details={"tools": list(lock.tools.keys())},
            )
            return

        changes = self.schema_pin.verify(tools)
        if not changes:
            return

        for change in changes:
            verdict = "block" if (
                (change.change_type == "added" and self.policy.filters.block_new_tools)
                or (
                    change.change_type == "modified"
                    and self.policy.filters.block_modified_tools
                )
            ) else "warn"

            self.audit.log(
                server=self.config.name,
                direction="inbound",
                method=method,
                tool=change.tool_name,
                verdict=verdict,
                reason=f"Schema {change.change_type}: {change.details}",
                details={
                    "old_hash": change.old_hash,
                    "new_hash": change.new_hash,
                },
            )

            if verdict == "block":
                logger.warning(
                    "SCHEMA DRIFT: %s — %s [%s]",
                    change.tool_name,
                    change.details,
                    change.change_type,
                )
