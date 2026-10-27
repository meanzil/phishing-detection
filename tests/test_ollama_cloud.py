import pytest

from ai.ollama_cloud import (
    analyze_with_ollama_cloud,
    ollama_cloud_is_configured,
)


def test_cloud_is_not_configured_without_api_key(monkeypatch):
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    assert ollama_cloud_is_configured() is False


def test_cloud_is_configured_with_nonempty_api_key(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "test-key-not-a-real-secret")
    assert ollama_cloud_is_configured() is True


def test_placeholder_key_is_not_treated_as_configured(monkeypatch):
    monkeypatch.setenv(
        "OLLAMA_API_KEY", "replace_with_your_ollama_cloud_api_key"
    )
    assert ollama_cloud_is_configured() is False


def test_analysis_fails_fast_without_api_key(monkeypatch):
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="OLLAMA_API_KEY"):
        analyze_with_ollama_cloud(
            subject="Example",
            sender="sender@example.test",
            body="Example email body",
        )
