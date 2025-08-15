"""PORTFAN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from portfan.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-portfan[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-portfan[mcp]'")
        return 1
    app = FastMCP("portfan")

    @app.tool()
    def portfan_scan(target: str) -> str:
        """Summarize and diff nmap XML into prioritized, attackable findings. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
