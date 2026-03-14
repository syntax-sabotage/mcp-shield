"""CLI for MCP Shield."""

from __future__ import annotations

import asyncio
import logging
import sys
import time

import click
from rich.console import Console
from rich.table import Table

from mcp_shield.audit import AuditLog
from mcp_shield.config import ShieldConfig, ServerConfig
from mcp_shield.policy import ServerPolicy
from mcp_shield.proxy import MCPProxyServer
from mcp_shield.schema_pin import SchemaPin

console = Console()


@click.group()
@click.version_option(package_name="mcp-shield")
def main():
    """MCP Shield — Security proxy for MCP servers.

    Intercepts MCP traffic between Claude Code and external servers.
    Provides schema pinning, secret scanning, and injection detection.
    """
    pass


@main.command()
@click.argument("name")
@click.argument("url")
@click.option(
    "--tier",
    type=click.Choice(["local", "org", "community", "unknown"]),
    default="unknown",
    help="Trust tier (controls default filter strictness)",
)
def add(name: str, url: str, tier: str):
    """Register an MCP server for proxying.

    Example:
        mcp-shield add pi-brain https://pi.ruv.io/sse --tier community
    """
    config = ShieldConfig.load()

    if name in config.servers:
        console.print(f"[yellow]Server '{name}' already registered. Updating.[/yellow]")

    port = config.servers[name].proxy_port if name in config.servers else config.next_port()
    config.servers[name] = ServerConfig(
        name=name,
        url=url,
        trust_tier=tier,
        proxy_port=port,
    )
    config.save()

    # Create tier-appropriate policy
    policy = ServerPolicy.for_tier(name, tier)
    policy.save()

    console.print(f"\n[green]Server '{name}' registered.[/green]\n")
    console.print(f"  Remote:  {url}")
    console.print(f"  Proxy:   http://{config.proxy_host}:{port}/sse")
    console.print(f"  Tier:    {tier}")
    console.print(f"  Policy:  ~/.mcp-shield/policies/{name}.yaml")
    console.print()
    console.print("[dim]To connect Claude Code through the shield:[/dim]")
    console.print(f"  1. mcp-shield start")
    console.print(f"  2. claude mcp add {name} --transport sse http://127.0.0.1:{port}/sse")


@main.command()
def ls():
    """List registered MCP servers."""
    config = ShieldConfig.load()

    if not config.servers:
        console.print("[dim]No servers registered. Use 'mcp-shield add' to register one.[/dim]")
        return

    table = Table(title="Registered MCP Servers")
    table.add_column("Name", style="cyan")
    table.add_column("URL", style="dim")
    table.add_column("Tier", style="yellow")
    table.add_column("Proxy Port", justify="right")
    table.add_column("Pinned", justify="center")
    table.add_column("Status")

    for name, server in config.servers.items():
        pin = SchemaPin(name)
        pinned = "[green]Yes[/green]" if pin.is_pinned else "[dim]No[/dim]"
        status = "[green]Enabled[/green]" if server.enabled else "[red]Disabled[/red]"
        table.add_row(
            server.name,
            server.url[:50] + ("..." if len(server.url) > 50 else ""),
            server.trust_tier,
            str(server.proxy_port),
            pinned,
            status,
        )

    console.print(table)


@main.command()
@click.argument("name")
def remove(name: str):
    """Unregister an MCP server."""
    config = ShieldConfig.load()

    if name not in config.servers:
        console.print(f"[red]Server '{name}' not found.[/red]")
        raise SystemExit(1)

    del config.servers[name]
    config.save()
    console.print(f"[green]Server '{name}' removed.[/green]")


@main.command()
@click.argument("name")
def pin(name: str):
    """Connect to server and pin current tool schemas."""
    config = ShieldConfig.load()
    if name not in config.servers:
        console.print(f"[red]Server '{name}' not found.[/red]")
        raise SystemExit(1)

    console.print(f"Connecting to {config.servers[name].url}...")
    console.print("[yellow]Schema pinning requires an active proxy connection.[/yellow]")
    console.print("Start the proxy with 'mcp-shield start' — schemas are pinned on first tools/list response.")


@main.command()
@click.argument("name")
def policy(name: str):
    """Show policy for a server."""
    p = ServerPolicy.load(name)

    console.print(f"\n[bold]Policy for '{name}'[/bold] (tier: {p.trust_tier})\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Filter", style="cyan")
    table.add_column("Setting")
    table.add_column("Value", justify="right")

    table.add_row("Outbound", "Secret scanning", _bool(p.filters.scan_secrets))
    table.add_row("", "Path sanitization", _bool(p.filters.sanitize_paths))
    table.add_row("", "Max param size", f"{p.filters.max_param_size:,}B")
    table.add_row("Inbound", "Injection detection", _bool(p.filters.detect_injection))
    table.add_row("", "Max response size", f"{p.filters.max_response_size:,}B")
    table.add_row("", "Strip system tags", _bool(p.filters.strip_system_tags))
    table.add_row("Schema", "Pin schemas", _bool(p.filters.pin_schemas))
    table.add_row("", "Block new tools", _bool(p.filters.block_new_tools))
    table.add_row("", "Block modified tools", _bool(p.filters.block_modified_tools))

    console.print(table)

    if p.allowed_tools:
        console.print(f"\n[green]Allowed tools:[/green] {', '.join(p.allowed_tools)}")
    if p.blocked_tools:
        console.print(f"\n[red]Blocked tools:[/red] {', '.join(p.blocked_tools)}")

    console.print(f"\n[dim]Edit: ~/.mcp-shield/policies/{name}.yaml[/dim]")


@main.command()
@click.option("--tail", "-n", default=20, help="Number of recent events to show")
@click.option("--server", "-s", default=None, help="Filter by server name")
@click.option("--verdict", "-v", default=None, type=click.Choice(["pass", "block", "warn", "modify"]))
def audit(tail: int, server: str | None, verdict: str | None):
    """View the audit log."""
    log = AuditLog()
    events = log.read(tail=tail * 3)  # read extra, then filter

    if server:
        events = [e for e in events if e.server == server]
    if verdict:
        events = [e for e in events if e.verdict == verdict]
    events = events[-tail:]

    if not events:
        console.print("[dim]No audit events found.[/dim]")
        return

    table = Table(title="Audit Log", show_lines=False)
    table.add_column("Time", style="dim", width=8)
    table.add_column("Server", style="cyan", width=12)
    table.add_column("Dir", width=4)
    table.add_column("Method", width=14)
    table.add_column("Tool", width=16)
    table.add_column("Verdict", width=7)
    table.add_column("Reason")

    for event in events:
        import datetime

        ts = datetime.datetime.fromtimestamp(event.timestamp).strftime("%H:%M:%S")
        direction = "[blue]OUT[/blue]" if event.direction == "outbound" else "[magenta]IN[/magenta]"
        verdict_style = {
            "pass": "[green]pass[/green]",
            "block": "[red]BLOCK[/red]",
            "warn": "[yellow]WARN[/yellow]",
            "modify": "[blue]mod[/blue]",
        }.get(event.verdict, event.verdict)

        table.add_row(
            ts,
            event.server,
            direction,
            event.method,
            event.tool or "",
            verdict_style,
            event.reason[:60] if event.reason else "",
        )

    console.print(table)


@main.command()
@click.option("--host", default=None, help="Proxy host (default: 127.0.0.1)")
@click.option("--server", "-s", default=None, help="Start proxy for specific server only")
def start(host: str | None, server: str | None):
    """Start the shield proxy for all registered servers."""
    config = ShieldConfig.load()

    if not config.servers:
        console.print("[red]No servers registered. Use 'mcp-shield add' first.[/red]")
        raise SystemExit(1)

    proxy_host = host or config.proxy_host
    servers_to_start = (
        {server: config.servers[server]}
        if server and server in config.servers
        else config.servers
    )

    if server and server not in config.servers:
        console.print(f"[red]Server '{server}' not found.[/red]")
        raise SystemExit(1)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    console.print("\n[bold green]MCP Shield starting...[/bold green]\n")

    audit_log = AuditLog()

    async def run():
        runners = []
        for name, srv in servers_to_start.items():
            if not srv.enabled:
                console.print(f"  [dim]Skipping {name} (disabled)[/dim]")
                continue

            policy = ServerPolicy.load(name)
            proxy = MCPProxyServer(srv, policy, audit_log)
            port = srv.proxy_port or config.next_port()
            runner = await proxy.start(proxy_host, port)
            runners.append(runner)

            pin_status = "[green]pinned[/green]" if SchemaPin(name).is_pinned else "[yellow]unpinned[/yellow]"
            console.print(
                f"  [cyan]{name}[/cyan] → http://{proxy_host}:{port}/sse "
                f"[dim]→ {srv.url}[/dim] ({pin_status})"
            )

        if not runners:
            console.print("[red]No servers to start.[/red]")
            return

        console.print(f"\n[green]Shield active. {len(runners)} server(s) proxied.[/green]")
        console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

        try:
            await asyncio.Event().wait()  # run forever
        except asyncio.CancelledError:
            pass
        finally:
            for runner in runners:
                await runner.cleanup()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Shield stopped.[/yellow]")


def _bool(val: bool) -> str:
    return "[green]On[/green]" if val else "[red]Off[/red]"


if __name__ == "__main__":
    main()
