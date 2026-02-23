"""Tests for the Anthropic instrumentation wrapper."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

from vaol.client import VAOLClient
from vaol.record import OutputMode, sha256_hash
from vaol.anthropic_wrapper import instrument_anthropic


# ---------------------------------------------------------------------------
# Helpers — mock Anthropic response objects
# ---------------------------------------------------------------------------

def _make_text_block(text: str = "Hello from Claude!") -> MagicMock:
    """Create a mock Anthropic TextBlock."""
    block = MagicMock()
    block.type = "text"
    block.text = text
    return block


def _make_tool_use_block(
    tool_id: str = "toolu_01",
    name: str = "get_weather",
    tool_input: dict | None = None,
) -> MagicMock:
    """Create a mock Anthropic tool_use ContentBlock."""
    block = MagicMock()
    block.type = "tool_use"
    block.id = tool_id
    block.name = name
    block.input = tool_input or {"location": "Paris"}
    # tool_use blocks do NOT have .text
    del block.text
    return block


def _make_anthropic_response(
    text: str = "Hello from Claude!",
    stop_reason: str = "end_turn",
    input_tokens: int = 10,
    output_tokens: int = 5,
    content_blocks: list | None = None,
) -> MagicMock:
    """Create a mock Anthropic Messages response."""
    usage = MagicMock()
    usage.input_tokens = input_tokens
    usage.output_tokens = output_tokens

    response = MagicMock()
    if content_blocks is not None:
        response.content = content_blocks
    else:
        response.content = [_make_text_block(text)]
    response.stop_reason = stop_reason
    response.usage = usage
    return response


def _make_mock_client(response: Any = None) -> MagicMock:
    """Create a mock Anthropic client with messages.create."""
    if response is None:
        response = _make_anthropic_response()
    client = MagicMock()
    client.messages.create = MagicMock(return_value=response)
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

class TestInstrumentAnthropic:
    def test_returns_original_response(self) -> None:
        """Instrumented client returns the Anthropic response unchanged."""
        anthropic_response = _make_anthropic_response(text="Paris is the capital.")
        anthropic_client = _make_mock_client(anthropic_response)
        vaol_client = _make_vaol_client()

        instrument_anthropic(anthropic_client, vaol_client, tenant_id="acme", subject="user-1")

        result = anthropic_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": "What is the capital of France?"}],
        )

        assert result is anthropic_response

    def test_replaces_create_method(self) -> None:
        """instrument_anthropic replaces messages.create."""
        anthropic_client = _make_mock_client()
        original = anthropic_client.messages.create
        vaol_client = _make_vaol_client()

        instrument_anthropic(anthropic_client, vaol_client, tenant_id="acme", subject="user-1")

        assert anthropic_client.messages.create is not original

    def test_forwards_arguments_to_anthropic(self) -> None:
        """All arguments are passed through to the original create method."""
        anthropic_response = _make_anthropic_response()
        original_create = MagicMock(return_value=anthropic_response)

        anthropic_client = MagicMock()
        anthropic_client.messages.create = original_create
        vaol_client = _make_vaol_client()

        instrument_anthropic(anthropic_client, vaol_client, tenant_id="acme", subject="user-1")

        anthropic_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello"}],
            temperature=0.7,
        )

        original_create.assert_called_once_with(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello"}],
            temperature=0.7,
        )

    def test_emits_record_to_vaol(self) -> None:
        """A DecisionRecord is sent to the VAOL server on success."""
        anthropic_client = _make_mock_client()
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_anthropic(anthropic_client, vaol_client, tenant_id="acme", subject="user-1")

            anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Hi"}],
            )

            mock_append.assert_called_once()
            record = mock_append.call_args[0][0]
            assert record.identity.tenant_id == "acme"
            assert record.identity.subject == "user-1"
            assert record.model.provider == "anthropic"
            assert record.model.name == "claude-sonnet-4-20250514"

    def test_captures_system_prompt_hash_from_string(self) -> None:
        """System prompt string is hashed when present as kwarg."""
        anthropic_client = _make_mock_client()
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_anthropic(anthropic_client, vaol_client, tenant_id="acme", subject="user-1")

            anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                system="You are a helpful assistant.",
                messages=[{"role": "user", "content": "Hello"}],
            )

            record = mock_append.call_args[0][0]
            expected = sha256_hash("You are a helpful assistant.")
            assert record.prompt_context.system_prompt_hash == expected

    def test_captures_system_prompt_hash_from_blocks(self) -> None:
        """System prompt as list of content blocks is hashed correctly."""
        anthropic_client = _make_mock_client()
        vaol_client = _make_vaol_client()

        system_blocks = [
            {"type": "text", "text": "You are a helpful assistant."},
            {"type": "text", "text": "Be concise."},
        ]

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_anthropic(anthropic_client, vaol_client, tenant_id="acme", subject="user-1")

            anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                system=system_blocks,
                messages=[{"role": "user", "content": "Hello"}],
            )

            record = mock_append.call_args[0][0]
            expected = sha256_hash(json.dumps(system_blocks, sort_keys=True, separators=(",", ":")))
            assert record.prompt_context.system_prompt_hash == expected

    def test_captures_output_hash(self) -> None:
        """Output text is hashed correctly."""
        anthropic_client = _make_mock_client(
            _make_anthropic_response(text="The answer is 42.")
        )
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_anthropic(anthropic_client, vaol_client, tenant_id="acme", subject="user-1")

            anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": "What is the meaning of life?"}],
            )

            record = mock_append.call_args[0][0]
            assert record.output.output_hash == sha256_hash("The answer is 42.")

    def test_captures_token_counts(self) -> None:
        """Token counts from usage are captured in the record."""
        anthropic_client = _make_mock_client(
            _make_anthropic_response(input_tokens=50, output_tokens=25)
        )
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_anthropic(anthropic_client, vaol_client, tenant_id="acme", subject="user-1")

            anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Count tokens"}],
            )

            record = mock_append.call_args[0][0]
            assert record.prompt_context.total_input_tokens == 50
            assert record.output.output_tokens == 25

    def test_captures_tool_schema_hash(self) -> None:
        """Tool schema is hashed when tools are provided."""
        tools = [{"name": "get_weather", "description": "Get weather", "input_schema": {}}]
        anthropic_client = _make_mock_client()
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_anthropic(anthropic_client, vaol_client, tenant_id="acme", subject="user-1")

            anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Weather?"}],
                tools=tools,
            )

            record = mock_append.call_args[0][0]
            expected = sha256_hash(json.dumps(tools, sort_keys=True, separators=(",", ":")))
            assert record.prompt_context.tool_schema_hash == expected

    def test_captures_tool_use_output(self) -> None:
        """tool_use content blocks are included in output hash."""
        tool_block = _make_tool_use_block(
            tool_id="toolu_01", name="get_weather", tool_input={"location": "Paris"}
        )
        response = _make_anthropic_response(
            content_blocks=[tool_block],
            stop_reason="tool_use",
        )
        anthropic_client = _make_mock_client(response)
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_anthropic(anthropic_client, vaol_client, tenant_id="acme", subject="user-1")

            anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Weather in Paris?"}],
            )

            record = mock_append.call_args[0][0]
            # The tool_use block should be serialized as JSON evidence
            tool_json = json.dumps(
                {"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {"location": "Paris"}},
                sort_keys=True,
                separators=(",", ":"),
            )
            assert record.output.output_hash == sha256_hash(tool_json)

    def test_vaol_failure_does_not_block_response(self) -> None:
        """If VAOL server is down, the Anthropic response still returns."""
        anthropic_response = _make_anthropic_response(text="still works")
        anthropic_client = _make_mock_client(anthropic_response)
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", side_effect=Exception("server down")):
            instrument_anthropic(anthropic_client, vaol_client, tenant_id="acme", subject="user-1")

            result = anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Hello"}],
            )

            assert result is anthropic_response

    def test_output_mode_passed_through(self) -> None:
        """Custom output_mode is respected."""
        anthropic_client = _make_mock_client()
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_anthropic(
                anthropic_client,
                vaol_client,
                tenant_id="acme",
                subject="user-1",
                output_mode=OutputMode.ENCRYPTED,
            )

            anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Test"}],
            )

            record = mock_append.call_args[0][0]
            assert record.output.mode == OutputMode.ENCRYPTED

    def test_finish_reason_captured(self) -> None:
        """stop_reason from Anthropic response is captured as finish_reason."""
        anthropic_client = _make_mock_client(
            _make_anthropic_response(stop_reason="max_tokens")
        )
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_anthropic(anthropic_client, vaol_client, tenant_id="acme", subject="user-1")

            anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Long story"}],
            )

            record = mock_append.call_args[0][0]
            assert record.output.finish_reason == "max_tokens"

    def test_message_count(self) -> None:
        """Message count is correctly captured from messages list."""
        anthropic_client = _make_mock_client()
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_anthropic(anthropic_client, vaol_client, tenant_id="acme", subject="user-1")

            anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[
                    {"role": "user", "content": "Hello"},
                    {"role": "assistant", "content": "Hi"},
                    {"role": "user", "content": "More"},
                ],
            )

            record = mock_append.call_args[0][0]
            assert record.prompt_context.message_count == 3

    def test_no_system_prompt_produces_empty_hash(self) -> None:
        """When no system prompt is given, system_prompt_hash is empty."""
        anthropic_client = _make_mock_client()
        vaol_client = _make_vaol_client()

        with patch.object(vaol_client, "append", return_value={"sequence_number": 0}) as mock_append:
            instrument_anthropic(anthropic_client, vaol_client, tenant_id="acme", subject="user-1")

            anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Hello"}],
            )

            record = mock_append.call_args[0][0]
            assert record.prompt_context.system_prompt_hash == ""
