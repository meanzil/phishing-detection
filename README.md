# AI-Powered Phishing Email Detection Using MCP

Starter project using Python, MCP, and Streamlit to inspect phishing indicators. The heuristic score is not a calibrated probability and can produce false positives and false negatives.

## Quick start — one command

After cloning the repository, run these commands once to create the environment and install dependencies:

```bash
python -m venv venv
# Windows: venv\\Scripts\\activate
# Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
```

Then start the **MCP HTTP server and Streamlit dashboard together** with:

```bash
python run.py
```

Open the dashboard at http://127.0.0.1:8501. The MCP endpoint is http://127.0.0.1:8000/mcp. Press Ctrl+C in the terminal to stop both processes. Ensure ports 8000 and 8501 are available.

## Run components separately

- Command-line example: `python main.py`
- Dashboard only: `streamlit run app.py`
- MCP server over stdio (for desktop MCP hosts): `python mcp_server.py`
- MCP server over HTTP: `python mcp_server.py --http`

The current dashboard uses the rule-based detector directly. A complete MCP-compatible client that sends tool results to an LLM is a future integration step; starting the MCP server does not itself make the dashboard call Ollama.

## Files

- `run.py`: one-command launcher for MCP HTTP server and dashboard
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
