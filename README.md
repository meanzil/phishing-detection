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

The MCP server exposes tools over stdio and must be launched by an MCP-compatible client; it does not itself call an LLM. The Streamlit app currently uses the rule-based detector directly. A complete MCP-compatible client that connects tool results to an LLM is a future integration step.

## Files

- `detector.py`: heuristic email and URL analysis
- `mcp_server.py`: MCP tools for email and URL inspection
- `app.py`: Streamlit dashboard
- `main.py`: command-line example
- `requirements.txt`: Python dependencies
- `tests/`: initial unit tests
- `docs/PROJECT_GUIDE.md`: architecture, setup, limitations, and roadmap

## Safety and validation

Treat emails as untrusted input. Never automatically open suspicious URLs or execute attachments. Avoid sending sensitive email content to external services without authorization, and do not commit secrets or real private email samples.

Evaluate with labeled examples and report precision, recall, F1, and false-positive rate. Do not claim 100% accuracy.