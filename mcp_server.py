from mcp.server.fastmcp import FastMCP

from detector import analyze_email, analyze_url, extract_urls

mcp = FastMCP("Phishing Detection Security Tools")


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
    mcp.run(transport="stdio")
