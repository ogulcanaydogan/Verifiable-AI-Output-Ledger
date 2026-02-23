"""Tests for the LiteLLM instrumentation wrapper."""

from __future__ import annotations

import json
import sys
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

from vaol.client import VAOLClient
from vaol.record import OutputMode, sha256_hash


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_litellm_response(
    content: str = "Hello from LiteLLM!",
    finish_reason: str = "stop",
    prompt_tokens: int = 10,
    completion_tokens: int = 5,
) -> MagicMock:
    """Create a mock LiteLLM response (OpenAI-normalized format)."""
    message = MagicMock()
    message.content = content

    choice = MagicMock()
    choice.message = message
    choice.finish_reason = finish_reason

    usage = MagicMock()
    usage.prompt_tokens = prompt_tokens
    usage.completion_tokens = completion_tokens

    response = MagicMock()
    response.choices = [choice]
    response.usage = usage
    return response


def _make_vaol_client() -> VAOLClient:
    """Create a VAOL client with mock transport that accepts any request."""
    transport = httpx.MockTransport(
        lambda req: httpx.Response(
            201,
            json={
                "request_id": "test-id",
                "sequence_number": 0,
                "record_hash": "sha256:abc",
            },
        )
    )
    client = VAOLClient.__new__(VAOLClient)
    client.server_url = "http://localhost:8080"
    client.tenant_id = "test-org"
    client._client = httpx.Client(transport=transport, base_url="http://localhost:8080")
    return client


@pytest.fixture(autouse=True)
def mock_litellm_module():
    """Inject a fake litellm module into sys.modules for tests."""
    fake = MagicMock()
    fake.completion = MagicMock(return_value=_make_litellm_response())
    # Ensure the idempotency guard attribute is absent initially
    if hasattr(fake.completion, "_vaol_instrumented"):
        del fake.completion._vaol_instrumented
    sys.modules["litellm"] = fake
    yield fake
    del sys.modules["litellm"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestInstrumentLiteLLM:
    def test_patches_litellm_completion(self, mock_litellm_module: MagicMock) -> None:
        """instrument_litellm replaces litellm.completion."""
        from vaol.litellm_wrapper import instrument_litellm

        original = mock_litellm_module.completion
        vaol_client = _make_vaol_client()

        instrument_litellm(vaol_client, tenant_id="acme")

        assert mock_litellm_module.completion is not original

    def test_returns_original_response(self, mock_litellm_module: MagicMock) -> None:
        """Instrumented completion returns the LiteLLM response unchanged."""
        from vaol.litellm_wrapper import instrument_litellm

        expected_response = _make_litellm_response(content="Paris is the capital.")
        mock_litellm_module.completion = MagicMock(return_value=expected_response)

        vaol_client = _make_vaol_client()
        instrument_litellm(vaol_client, tenant_id="acme")

        result = mock_litellm_module.completion(
            model="openai/gpt-4o",
            messages=[{"role": "user", "content": "What is the capital of France?"}],
        )

        assert result is expected_response

    def test_emits_record_to_vaol(self, mock_litellm_module: MagicMock) -> None:
        """A DecisionRecord is sent to the VAOL server on success."""
        from vaol.litellm_wrapper import instrument_litellm

        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_litellm(vaol_client, tenant_id="acme", subject="user-1")

            mock_litellm_module.completion(
                model="anthropic/claude-sonnet-4-20250514",
                messages=[{"role": "user", "content": "Hi"}],
            )

            mock_append.assert_called_once()
            record = mock_append.call_args[0][0]
            assert record.identity.tenant_id == "acme"
            assert record.identity.subject == "user-1"
            assert record.model.provider == "anthropic"
            assert record.model.name == "claude-sonnet-4-20250514"

    def test_parses_provider_from_model_string(self, mock_litellm_module: MagicMock) -> None:
        """Provider is parsed from model string like 'openai/gpt-4o'."""
        from vaol.litellm_wrapper import instrument_litellm

        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_litellm(vaol_client, tenant_id="acme")

            mock_litellm_module.completion(
                model="openai/gpt-4o",
                messages=[{"role": "user", "content": "Hello"}],
            )

            record = mock_append.call_args[0][0]
            assert record.model.provider == "openai"
            assert record.model.name == "gpt-4o"

    def test_unknown_provider_for_bare_model(self, mock_litellm_module: MagicMock) -> None:
        """Model without provider prefix yields provider='unknown'."""
        from vaol.litellm_wrapper import instrument_litellm

        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_litellm(vaol_client, tenant_id="acme")

            mock_litellm_module.completion(
                model="gpt-4o",
                messages=[{"role": "user", "content": "Hello"}],
            )

            record = mock_append.call_args[0][0]
            assert record.model.provider == "unknown"
            assert record.model.name == "gpt-4o"

    def test_captures_system_prompt_hash(self, mock_litellm_module: MagicMock) -> None:
        """System prompt from messages list is hashed."""
        from vaol.litellm_wrapper import instrument_litellm

        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_litellm(vaol_client, tenant_id="acme")

            mock_litellm_module.completion(
                model="openai/gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "Hello"},
                ],
            )

            record = mock_append.call_args[0][0]
            expected = sha256_hash("You are a helpful assistant.")
            assert record.prompt_context.system_prompt_hash == expected

    def test_captures_output_hash(self, mock_litellm_module: MagicMock) -> None:
        """Output text is hashed correctly."""
        mock_litellm_module.completion = MagicMock(
            return_value=_make_litellm_response(content="The answer is 42.")
        )
        from vaol.litellm_wrapper import instrument_litellm

        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_litellm(vaol_client, tenant_id="acme")

            mock_litellm_module.completion(
                model="openai/gpt-4o",
                messages=[{"role": "user", "content": "Meaning of life?"}],
            )

            record = mock_append.call_args[0][0]
            assert record.output.output_hash == sha256_hash("The answer is 42.")

    def test_captures_token_counts(self, mock_litellm_module: MagicMock) -> None:
        """Token counts from usage are captured in the record."""
        mock_litellm_module.completion = MagicMock(
            return_value=_make_litellm_response(prompt_tokens=50, completion_tokens=25)
        )
        from vaol.litellm_wrapper import instrument_litellm

        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_litellm(vaol_client, tenant_id="acme")

            mock_litellm_module.completion(
                model="openai/gpt-4o",
                messages=[{"role": "user", "content": "Count tokens"}],
            )

            record = mock_append.call_args[0][0]
            assert record.prompt_context.total_input_tokens == 50
            assert record.output.output_tokens == 25

    def test_vaol_failure_does_not_block_response(self, mock_litellm_module: MagicMock) -> None:
        """If VAOL server is down, the LiteLLM response still returns."""
        expected = _make_litellm_response(content="still works")
        mock_litellm_module.completion = MagicMock(return_value=expected)

        from vaol.litellm_wrapper import instrument_litellm

        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", side_effect=Exception("server down")):
            instrument_litellm(vaol_client, tenant_id="acme")

            result = mock_litellm_module.completion(
                model="openai/gpt-4o",
                messages=[{"role": "user", "content": "Hello"}],
            )

            assert result is expected

    def test_idempotent_instrumentation(self, mock_litellm_module: MagicMock) -> None:
        """Calling instrument_litellm twice doesn't double-wrap."""
        from vaol.litellm_wrapper import instrument_litellm

        vaol_client = _make_vaol_client()

        instrument_litellm(vaol_client, tenant_id="acme")
        wrapped_first = mock_litellm_module.completion

        instrument_litellm(vaol_client, tenant_id="acme")
        wrapped_second = mock_litellm_module.completion

        # Should be the same function — second call is a no-op
        assert wrapped_first is wrapped_second
