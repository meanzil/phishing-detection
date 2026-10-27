import argparse

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

from detector import analyze_email, analyze_url, extract_urls

# Keep the HTTP MCP endpoint bound to localhost for local development.
mcp = FastMCP(
    "Phishing Detection Security Tools",
    host="127.0.0.1",
    port=8000,
)


@mcp.custom_route("/", methods=["GET"])
async def root_status(request: Request):
    """Informative status page for browser users checking the MCP server."""
    accept = request.headers.get("accept", "")
    if "application/json" in accept and "text/html" not in accept:
        return JSONResponse({
            "status": "online",
            "server": "Phishing Detection Security Tools",
            "transport": "streamable-http",
            "mcp_endpoint": "http://127.0.0.1:8000/mcp",
            "tools": ["inspect_email", "inspect_url", "find_email_urls"],
        })

    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>MCP Security Server Status</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px 20px; margin: 0; }
            .card { max-width: 580px; margin: 0 auto; background: #1e293b; border: 1px solid #334155; border-radius: 16px; padding: 28px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
            h2 { color: #38bdf8; margin-top: 0; display: flex; align-items: center; gap: 10px; }
            .badge { background: #065f46; color: #34d399; font-size: 0.8rem; font-weight: 700; padding: 4px 10px; border-radius: 9999px; text-transform: uppercase; }
            .info-box { background: #0f172a; border: 1px solid #334155; border-radius: 10px; padding: 14px 16px; margin: 18px 0; font-size: 0.95rem; }
            code { background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; color: #38bdf8; font-family: monospace; }
            .note { color: #94a3b8; font-size: 0.88rem; line-height: 1.5; border-left: 3px solid #38bdf8; padding-left: 12px; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>🛡️ MCP Security Server <span class="badge">Online</span></h2>
            <p>The Model Context Protocol (MCP) server is running and ready to handle security tool requests from clients.</p>
            <div class="info-box">
                <p style="margin: 4px 0;"><strong>Active Endpoint:</strong> <code>http://127.0.0.1:8000/mcp</code></p>
                <p style="margin: 4px 0;"><strong>Protocol:</strong> Streamable HTTP (SSE - Server-Sent Events)</p>
                <p style="margin: 4px 0;"><strong>Registered Tools:</strong> <code>inspect_email</code>, <code>inspect_url</code>, <code>find_email_urls</code></p>
            </div>
            <div class="note">
                <strong>Why does opening <code>/mcp</code> directly show a JSON-RPC error?</strong><br>
                Web browsers send a standard <code>text/html</code> header. The MCP protocol strictly requires <code>Accept: text/event-stream</code>.
                Use the <strong>Streamlit Dashboard</strong> at <code>http://127.0.0.1:8501</code> to interact with these tools seamlessly.
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(html.strip())


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request):
    """Health check route returning JSON status."""
    return JSONResponse({
        "status": "healthy",
        "service": "Phishing Detection MCP Server",
        "endpoint": "/mcp",
    })


@mcp.tool()
def inspect_email(subject: str, sender: str, body: str) -> dict:
    """Analyze an email and return basic phishing indicators."""
    return analyze_email(subject, sender, body)


@mcp.tool()
def inspect_url(url: str) -> dict:
    """Inspect a URL as text; do not visit it."""
    return {"url": url, "findings": analyze_url(url)}


@mcp.tool()
def find_email_urls(body: str) -> dict:
    """Extract URL-looking strings from email content."""
    return {"urls": extract_urls(body)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phishing detection MCP server")
    parser.add_argument(
        "--http",
        action="store_true",
        help="Use Streamable HTTP at http://127.0.0.1:8000/mcp",
    )
    args = parser.parse_args()

    if args.http:
        mcp.run(transport="streamable-http")
    else:
        # Default stdio mode remains compatible with desktop MCP clients.
        mcp.run(transport="stdio")
