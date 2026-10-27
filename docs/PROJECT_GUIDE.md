# AI-Powered Phishing Email Detection Using MCP

## Objective
Build a modular email-analysis tool that combines deterministic checks with MCP tools and, in a later phase, an LLM that explains the evidence. MCP is the tool-connection protocol; it is not a phishing detector or an AI model.

## Architecture
1. Streamlit accepts an email subject, sender, and body.
2. Python extracts URL-looking strings and runs heuristic checks.
3. The MCP server exposes `inspect_email`, `inspect_url`, and `find_email_urls` tools over stdio.
4. An MCP-compatible client can invoke tools and pass their results to a selected LLM, such as a local Ollama model.
5. The UI displays a classification, heuristic score, findings, and extracted URLs.

## Tool stack
- Python 3.10+
- Streamlit for the UI
- `tldextract` and `urllib.parse` for basic URL parsing
- Official Python MCP SDK (`mcp[cli]`) for tool exposure
- Pytest for tests
- Ollama as an optional local LLM runtime for a future MCP-client integration

## Setup

```bash
python -m venv venv
# Windows: venv\\Scripts\\activate
# Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
```

Run the command-line sample with `python main.py`, the UI with `streamlit run app.py`, and the MCP server with `python mcp_server.py`. The server uses stdio and expects an MCP-compatible client. The included app currently calls the rule-based detector directly; a full MCP + LLM orchestration client remains a next step.

## MCP tools
- `inspect_email(subject, sender, body)`: return heuristic email analysis.
- `inspect_url(url)`: inspect URL text without visiting it.
- `find_email_urls(body)`: extract URL-looking strings.

## Known limitations
The current risk score is an illustrative heuristic, not a calibrated probability. The URL checks are deliberately simple; they do not establish domain ownership, validate SPF/DKIM/DMARC, or prove a URL is malicious. A message may be malicious even when no indicator is found, and legitimate emails may trigger warnings.

## Security and privacy
- Never automatically open suspicious URLs or execute email attachments.
- Treat email content as untrusted input; it may contain prompt-injection instructions aimed at the LLM.
- Do not share sensitive email content with external providers unless authorized.
- Do not commit API keys, credentials, private email samples, or sensitive attachments.
- Apply timeouts, rate limits, and provider terms to threat-intelligence integrations.

## Evaluation roadmap
Use a labeled dataset containing legitimate and phishing emails, with separate train/test splits where applicable. Report precision, recall, F1 score, false-positive rate, and false-negative rate. Add robust `.eml` parsing, authentication-header interpretation, threat-intelligence results, analyst feedback, and PDF report generation incrementally. Do not claim 100% accuracy.
