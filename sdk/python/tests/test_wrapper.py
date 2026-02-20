"""Tests for the OpenAI instrumentation wrapper."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

from vaol.client import VAOLClient
from vaol.record import OutputMode, sha256_hash
from vaol.wrapper import instrument_openai


# ---------------------------------------------------------------------------
# Helpers — mock OpenAI response objects
# ---------------------------------------------------------------------------

def _make_openai_response(
    content: str = "Hello from GPT!",
    finish_reason: str = "stop",
    prompt_tokens: int = 10,
    completion_tokens: int = 5,
) -> MagicMock:
    """Create a mock OpenAI ChatCompletion response."""
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


def _make_mock_client(response: Any = None) -> MagicMock:
    """Create a mock OpenAI client with chat.completions.create."""
    if response is None:
        response = _make_openai_response()

    client = MagicMock()
    client.chat.completions.create = MagicMock(return_value=response)
    return client


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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestInstrumentOpenAI:
    def test_returns_original_response(self) -> None:
        """Instrumented client returns the OpenAI response unchanged."""
        openai_response = _make_openai_response(content="Paris is the capital.")
        openai_client = _make_mock_client(openai_response)
        vaol_client = _make_vaol_client()

        instrument_openai(openai_client, vaol_client, tenant_id="acme", subject="user-1")

        result = openai_client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "What is the capital of France?"}],
        )

        assert result is openai_response

    def test_replaces_create_method(self) -> None:
        """instrument_openai replaces chat.completions.create."""
        openai_client = _make_mock_client()
        original = openai_client.chat.completions.create
        vaol_client = _make_vaol_client()

        instrument_openai(openai_client, vaol_client, tenant_id="acme", subject="user-1")

        assert openai_client.chat.completions.create is not original

    def test_forwards_arguments_to_openai(self) -> None:
        """All arguments are passed through to the original create method."""
        openai_response = _make_openai_response()
        original_create = MagicMock(return_value=openai_response)

        openai_client = MagicMock()
        openai_client.chat.completions.create = original_create
        vaol_client = _make_vaol_client()

        instrument_openai(openai_client, vaol_client, tenant_id="acme", subject="user-1")

        openai_client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello"}],
            temperature=0.7,
            max_tokens=100,
        )

        original_create.assert_called_once_with(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello"}],
            temperature=0.7,
            max_tokens=100,
        )

    def test_emits_record_to_vaol(self) -> None:
        """A DecisionRecord is sent to the VAOL server on success."""
        openai_client = _make_mock_client()
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_openai(openai_client, vaol_client, tenant_id="acme", subject="user-1")

            openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "Hi"}],
            )

            mock_append.assert_called_once()
            record = mock_append.call_args[0][0]
            assert record.identity.tenant_id == "acme"
            assert record.identity.subject == "user-1"
            assert record.model.provider == "openai"
            assert record.model.name == "gpt-4o"

    def test_captures_system_prompt_hash(self) -> None:
        """System prompt is hashed separately when present."""
        openai_client = _make_mock_client()
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_openai(openai_client, vaol_client, tenant_id="acme", subject="user-1")

            openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "Hello"},
                ],
            )

            record = mock_append.call_args[0][0]
            expected_sys_hash = sha256_hash("You are a helpful assistant.")
            assert record.prompt_context.system_prompt_hash == expected_sys_hash

    def test_captures_output_hash(self) -> None:
        """Output text is hashed correctly."""
        openai_client = _make_mock_client(_make_openai_response(content="The answer is 42."))
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_openai(openai_client, vaol_client, tenant_id="acme", subject="user-1")

            openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "What is the meaning of life?"}],
            )

            record = mock_append.call_args[0][0]
            assert record.output.output_hash == sha256_hash("The answer is 42.")

    def test_captures_token_counts(self) -> None:
        """Token counts from usage are captured in the record."""
        openai_client = _make_mock_client(
            _make_openai_response(prompt_tokens=50, completion_tokens=25)
        )
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_openai(openai_client, vaol_client, tenant_id="acme", subject="user-1")

            openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "Count tokens"}],
            )

            record = mock_append.call_args[0][0]
            assert record.prompt_context.total_input_tokens == 50
            assert record.output.output_tokens == 25

    def test_captures_tool_schema_hash(self) -> None:
        """Tool schema is hashed when tools are provided."""
        tools = [{"type": "function", "function": {"name": "get_weather"}}]
        openai_client = _make_mock_client()
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_openai(openai_client, vaol_client, tenant_id="acme", subject="user-1")

            openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "Weather?"}],
                tools=tools,
            )

            record = mock_append.call_args[0][0]
            expected = sha256_hash(json.dumps(tools, sort_keys=True, separators=(",", ":")))
            assert record.prompt_context.tool_schema_hash == expected

    def test_captures_parameters(self) -> None:
        """Temperature, top_p, max_tokens are captured in parameters."""
        openai_client = _make_mock_client()
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_openai(openai_client, vaol_client, tenant_id="acme", subject="user-1")

            openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "Test"}],
                temperature=0.5,
                top_p=0.9,
                max_tokens=200,
            )

            record = mock_append.call_args[0][0]
            assert record.parameters.temperature == 0.5
            assert record.parameters.top_p == 0.9
            assert record.parameters.max_tokens == 200

    def test_vaol_failure_does_not_block_response(self) -> None:
        """If VAOL server is down, the OpenAI response still returns."""
        openai_response = _make_openai_response(content="still works")
        openai_client = _make_mock_client(openai_response)
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", side_effect=Exception("server down")):
            instrument_openai(openai_client, vaol_client, tenant_id="acme", subject="user-1")

            result = openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "Hello"}],
            )

            assert result is openai_response

    def test_output_mode_passed_through(self) -> None:
        """Custom output_mode is respected."""
        openai_client = _make_mock_client()
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_openai(
                openai_client,
                vaol_client,
                tenant_id="acme",
                subject="user-1",
                output_mode=OutputMode.ENCRYPTED,
            )

            openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "Test"}],
            )

            record = mock_append.call_args[0][0]
            assert record.output.mode == OutputMode.ENCRYPTED

    def test_finish_reason_captured(self) -> None:
        """Finish reason from OpenAI response is captured."""
        openai_client = _make_mock_client(
            _make_openai_response(finish_reason="length")
        )
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_openai(openai_client, vaol_client, tenant_id="acme", subject="user-1")

            openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "Long"}],
            )

            record = mock_append.call_args[0][0]
            assert record.output.finish_reason == "length"

    def test_message_count(self) -> None:
        """Message count is correctly captured from messages list."""
        openai_client = _make_mock_client()
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_openai(openai_client, vaol_client, tenant_id="acme", subject="user-1")

            openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "System"},
                    {"role": "user", "content": "Hello"},
                    {"role": "assistant", "content": "Hi"},
                    {"role": "user", "content": "More"},
                ],
            )

            record = mock_append.call_args[0][0]
            assert record.prompt_context.message_count == 4
