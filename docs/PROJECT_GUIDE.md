# AI-Powered Phishing Email Detection Using MCP

## Objective

Build a modular email-analysis tool that combines deterministic security checks, MCP tools, and an Ollama Cloud language model that explains evidence. MCP connects AI applications with tools; it is not itself a phishing detection algorithm or an LLM.

## Architecture

1. Streamlit accepts an email subject, sender, and body.
2. Python runs local heuristic analysis and extracts URL-looking strings.
3. The MCP server exposes `inspect_email`, `inspect_url`, and `find_email_urls` over Streamable HTTP or stdio.
4. Only after the user checks the consent box, the AI integration connects to the local MCP server and collects evidence by calling those tools.
5. The integration sends the email and MCP evidence to Ollama Cloud through its OpenAI-compatible API.
6. The dashboard displays local findings and the model's assessment.

## Technology stack

- Python 3.10+
- Streamlit
- `tldextract` and `urllib.parse` for basic URL parsing
- Official Python MCP SDK (`mcp[cli]`)
- OpenAI Python SDK for Ollama's OpenAI-compatible API
- `python-dotenv` for local environment configuration
- Pytest for tests

## Setup

Install dependencies in a virtual environment:

```bash
python -m venv venv
# Activate the virtual environment for your OS
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and set `OLLAMA_API_KEY` to an API key created in your Ollama account. Configure:

```dotenv
OLLAMA_API_KEY=your_real_key_here
OLLAMA_BASE_URL=https://ollama.com/v1
OLLAMA_MODEL=gemma4:31b
MCP_SERVER_URL=http://127.0.0.1:8000/mcp
```

Use a model available to your account. Never commit `.env`. The repository ignores `.env` and includes only a placeholder in `.env.example`.

Start both services together:

```bash
python run.py
```

Open http://127.0.0.1:8501. The local MCP endpoint is http://127.0.0.1:8000/mcp. On the dashboard, check the consent box before using the Ollama Cloud assessment. Without consent, email fields are analyzed only by the local rule-based detector.

## MCP tools

- `inspect_email(subject, sender, body)`: return heuristic email analysis.
- `inspect_url(url)`: inspect URL text without visiting it.
- `find_email_urls(body)`: extract URL-looking strings.

The AI integration calls these tools through an MCP client, then supplies the results to the cloud model.

## Environment variables

| Variable | Purpose |
|---|---|
| `OLLAMA_API_KEY` | Secret API key for Ollama Cloud |
| `OLLAMA_BASE_URL` | Defaults to `https://ollama.com/v1` |
| `OLLAMA_MODEL` | Defaults to `gemma4:31b`; choose a model available to your account |
| `MCP_SERVER_URL` | Defaults to `http://127.0.0.1:8000/mcp` |

Rotate the key if it is accidentally exposed. Keep it only in the local `.env` or a server-side secret manager.

## Known limitations

The current risk score is an illustrative heuristic, not a calibrated probability. URL checks do not establish ownership, validate SPF/DKIM/DMARC, or prove a URL is malicious. The AI can be wrong and may miss or misinterpret indicators. This integration does not claim to detect every phishing message and does not query an external URL reputation service.

## Security and privacy

- Suspicious URLs are inspected as strings and are never opened by the detector.
- Email bodies are untrusted and may contain prompt-injection attempts.
- Email subject, sender, body, and collected evidence are sent to Ollama Cloud only after explicit consent in the UI. Do not submit sensitive email unless authorized.
- Do not commit API keys, credentials, private email samples, or sensitive attachments.
- Keep the local MCP endpoint bound to localhost unless authentication and network controls are added.

## Evaluation roadmap

Use a labeled dataset containing legitimate and phishing emails. Report precision, recall, F1, false-positive rate, and false-negative rate. Potential improvements include robust `.eml` parsing, interpreting SPF/DKIM/DMARC results, optional reputation lookups, analyst feedback, PDF report generation, and automated evaluation.
