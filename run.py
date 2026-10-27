"""Start the local MCP HTTP server and Streamlit dashboard together.

Run: python run.py
Stop both services with Ctrl+C.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MCP_HOST = "127.0.0.1"
MCP_PORT = 8000
DASHBOARD_PORT = 8501


def wait_for_port(
    process: subprocess.Popen,
    host: str,
    port: int,
    timeout: float = 20.0,
) -> None:
    """Wait until the server accepts TCP connections or fail clearly."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"MCP server exited early with code {process.returncode}. "
                "Check whether port 8000 is already in use."
            )
        try:
            with socket.create_connection((host, port), timeout=0.4):
                return
        except OSError:
            time.sleep(0.25)

    raise RuntimeError(
        f"MCP server did not become ready on {host}:{port} within {timeout:g}s."
    )


def stop_process(process: subprocess.Popen | None) -> None:
    """Stop a child process and force-kill it if it does not exit promptly."""
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    mcp_process: subprocess.Popen | None = None
    dashboard_process: subprocess.Popen | None = None

    try:
        print("Starting MCP server at http://127.0.0.1:8000/mcp ...", flush=True)
        mcp_process = subprocess.Popen(
            [sys.executable, str(ROOT / "mcp_server.py"), "--http"],
            cwd=ROOT,
        )
        wait_for_port(mcp_process, MCP_HOST, MCP_PORT)

        print("Starting Streamlit dashboard ...", flush=True)
        dashboard_process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                str(ROOT / "app.py"),
                "--server.address",
                "127.0.0.1",
                "--server.port",
                str(DASHBOARD_PORT),
            ],
            cwd=ROOT,
        )

        print("\nServices started:", flush=True)
        print("  Dashboard: http://127.0.0.1:8501", flush=True)
        print("  MCP endpoint: http://127.0.0.1:8000/mcp", flush=True)
        print("Press Ctrl+C to stop both services.\n", flush=True)

        while True:
            if mcp_process.poll() is not None:
                print(
                    f"MCP server exited with code {mcp_process.returncode}.",
                    file=sys.stderr,
                )
                return mcp_process.returncode or 1
            if dashboard_process.poll() is not None:
                return dashboard_process.returncode or 0
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\nStopping services...", flush=True)
        return 0
    except (OSError, RuntimeError) as exc:
        print(f"Startup error: {exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        stop_process(dashboard_process)
        stop_process(mcp_process)


if __name__ == "__main__":
    raise SystemExit(main())
