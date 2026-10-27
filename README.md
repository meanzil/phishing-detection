# AI-Powered Phishing Email Detection Using MCP

Starter project using Python, MCP, and Streamlit to inspect phishing indicators. The heuristic score is not a calibrated probability and can produce false positives and false negatives.

## Setup

```bash
python -m venv venv
# Windows: venv\\Scripts\\activate
# Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
```

Run the detector with `python main.py`, the dashboard with `streamlit run app.py`, or the MCP server with `python mcp_server.py`.

The MCP server exposes tools over stdio and must be launched by an MCP-compatible client; it does not itself call an LLM. Treat emails as untrusted input, never automatically open suspicious URLs or execute attachments, and do not commit secrets or real private emails.

## Files

- `detector.py`: heuristic email and URL analysis
- `mcp_server.py`: MCP tools for email and URL inspection
- `app.py`: Streamlit dashboard
- `main.py`: command-line sample
- `tests/`: initial tests
- `docs/`: project guide PDF

Evaluate with labeled examples and report precision, recall, F1, and false-positive rate. Do not claim 100% accuracy.
