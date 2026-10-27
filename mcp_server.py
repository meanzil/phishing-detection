import argparse

from mcp.server.fastmcp import FastMCP

from detector import analyze_email, analyze_url, extract_urls

# Keep the HTTP MCP endpoint bound to localhost for local development.
mcp = FastMCP(
    "Phishing Detection Security Tools",
    host="127.0.0.1",
    port=8000,
)


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
