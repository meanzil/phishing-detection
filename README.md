# AI-Powered Phishing Email Detection Using MCP

A Python project that combines rule-based phishing indicators, MCP security tools, Ollama Cloud AI explanations, and a Streamlit dashboard.

> **Prototype limitation:** The rule-based score is heuristic, not a calibrated probability. It can produce false positives and false negatives. AI-generated explanations are also fallible.

## Features

- Analyze email subject, sender, and body with local Python rules
- Extract suspicious URLs and inspect URL strings without opening them
- Expose email and URL analysis as MCP tools
- Collect evidence with an MCP client, then send that evidence to Ollama Cloud for an AI explanation
- View results in a Streamlit dashboard
- Require explicit consent before email content is sent to Ollama Cloud

## 1. Install once

Python 3.10+ is recommended.

```bash
git clone https://github.com/meanzil/phishing-detection.git
cd phishing-detection
python -m venv venv
```

Activate the environment:

**Windows PowerShell**
```powershell
.\venv\Scripts\Activate.ps1
```

**Windows Command Prompt**
```bat
venv\Scripts\activate.bat
```

**Linux/macOS**
```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## 2. Configure Ollama Cloud

1. Create an Ollama Cloud API key in your Ollama account.
2. Copy the sample environment file.

   **Windows PowerShell**
   ```powershell
   Copy-Item .env.example .env
   ```

   **Linux/macOS**
   ```bash
   cp .env.example .env
   ```

3. Open `.env` and replace `replace_with_your_ollama_cloud_api_key` with your real key. You can change `OLLAMA_MODEL` to another model available to your account.

Example configuration (use your own key; never commit a real key):

```dotenv
OLLAMA_API_KEY=your_real_key_here
OLLAMA_BASE_URL=https://ollama.com/v1
OLLAMA_MODEL=gemma4:31b
MCP_SERVER_URL=http://127.0.0.1:8000/mcp
```

The key is read server-side from `.env` or environment variables. The repository ignores `.env`; never put the key in Python source or paste it into a public issue.

## 3. Start everything with one command

```bash
python run.py
```

Open the dashboard at **http://127.0.0.1:8501**. The local MCP endpoint is **http://127.0.0.1:8000/mcp**. Keep the terminal open and press Ctrl+C to stop both processes. Ports 8000 and 8501 must be available.

To use AI, enter an email and check the consent box explaining that the subject, sender, and body will be sent to Ollama Cloud. If unchecked, the app only runs local rule-based checks. When consent is given, the integration calls the local MCP tools to gather email and URL evidence, then asks Ollama Cloud to explain the evidence.

## Run components separately

- Command-line sample: `python main.py`
- Dashboard only: `streamlit run app.py`
- MCP server over stdio for local MCP hosts: `python mcp_server.py`
- MCP server over Streamable HTTP: `python mcp_server.py --http`
- Unit tests: `pytest -q`

The dashboard needs the local MCP server running for cloud AI analysis. The one-command launcher starts both. Starting an MCP server does not itself start or call a language model.

## Troubleshooting MCP or dashboard startup

Use the same terminal and Python environment for every command. On Windows, run these from the repository folder with the virtual environment activated:

```powershell
python --version
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -c "from mcp import ClientSession; from mcp.client.streamable_http import streamable_http_client; from mcp.server.fastmcp import FastMCP; import streamlit, openai, dotenv; print('Dependency imports OK')"
python -m pytest -q
python run.py
```

The project uses MCP SDK 1.x (minimum 1.30) to match its FastMCP server and HTTP client APIs. Reinstall dependencies after pulling updates; do not install an unrelated MCP 2.x version into this environment.

Common errors:

- `ModuleNotFoundError` for `mcp`, `streamlit`, `openai`, or `dotenv`: activate the project's virtual environment, then run `python -m pip install -r requirements.txt`.
- `Address already in use` or a message about port 8000: stop the older MCP process, or close the application using port 8000. Port 8501 must also be free for the dashboard.
- Dashboard shows an MCP connection error: keep `python run.py` running and confirm `MCP_SERVER_URL=http://127.0.0.1:8000/mcp` in `.env`.
- HTTP 401 from Ollama Cloud: the API key is missing, invalid, or copied incorrectly. Replace it in local `.env`, then fully stop and restart the app.
- HTTP 403: verify Ollama account/model access.
- HTTP 404: verify `OLLAMA_BASE_URL=https://ollama.com/v1` and set `OLLAMA_MODEL` to a model available to your account.
- HTTP 429: check the Ollama Cloud account's usage or rate limits.
- Local-only analysis works but cloud AI fails: that usually means the dashboard and local rules loaded successfully; focus on MCP connectivity or Ollama Cloud configuration shown by the error message.

Do not paste your API key or private email contents into an issue. If the error remains, share the full terminal traceback and the exact dashboard error text after removing any secrets.

## Project files

- `app.py`: Streamlit dashboard and AI consent flow
- `detector.py`: heuristic email and URL analysis
- `mcp_server.py`: MCP tools for email and URL inspection
- `ai/ollama_cloud.py`: MCP evidence collection and Ollama Cloud API integration
- `run.py`: starts MCP HTTP server and dashboard together
- `.env.example`: sample configuration without a real secret
- `requirements.txt`: project dependencies
- `tests/`: unit tests
- `docs/PROJECT_GUIDE.md`: architecture and development guide

## Safety and validation

- Never automatically open suspicious URLs or execute email attachments.
- Treat email content as untrusted data, including prompt-injection attempts.
- Email content is sent to Ollama Cloud only when the user checks the consent box. Do not submit private or sensitive email unless authorized.
- This starter integration does not query a commercial URL reputation service.
- Keep API keys in environment variables or a secret manager.
- Evaluate using labeled legitimate and phishing emails; report precision, recall, F1, and false-positive/negative rates. Do not claim 100% accuracy.

## Official references

- [Ollama Cloud models and API](https://ollama.com/blog/cloud-models)
- [Gemma 4 model page and cloud API example](https://ollama.com/library/gemma4:31b-cloud)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [Streamlit](https://streamlit.io/)
