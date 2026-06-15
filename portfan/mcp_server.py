"""PORTFAN MCP server — exposes portfan_scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from portfan.core import parse_nmap_xml, summarize


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-portfan[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install the MCP extra: pip install 'cognis-portfan[mcp]'")
        return 1
    app = FastMCP("portfan")

    @app.tool()
    def portfan_scan(xml_content: str) -> str:
        """Summarize nmap XML into prioritized triage findings. Returns JSON."""
        try:
            reports = parse_nmap_xml(xml_content)
            result = summarize(reports)
        except ValueError as exc:
            return json.dumps({"error": str(exc)})
        return json.dumps(result, indent=2)

    app.run()
    return 0
