"""Anthropic client wrapper that automatically emits VAOL DecisionRecords.

Usage:
    from anthropic import Anthropic
    import vaol

    client = Anthropic()
    vaol_client = vaol.VAOLClient("http://localhost:8080")
    wrapped = vaol.instrument_anthropic(client, vaol_client, tenant_id="my-org")

    # Use exactly like the standard Anthropic client
    response = wrapped.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Hello!"}],
    )
    # A DecisionRecord is automatically emitted to VAOL
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from vaol.client import VAOLClient
from vaol.record import (
    DecisionRecord,
    Identity,
    ModelInfo,
    Output,
    OutputMode,
    Parameters,
    PolicyContext,
    PolicyDecision,
    PromptContext,
    sha256_hash,
)

logger = logging.getLogger("vaol.anthropic_wrapper")


def instrument_anthropic(
    client: Any,
    vaol_client: VAOLClient,
    tenant_id: str,
    subject: str = "sdk-user",
    output_mode: OutputMode = OutputMode.HASH_ONLY,
) -> Any:
    """Wrap an Anthropic client to automatically emit VAOL DecisionRecords.

    Args:
        client: An Anthropic client instance.
        vaol_client: A VAOL server client.
        tenant_id: The tenant identifier.
        subject: The user/service identifier.
        output_mode: How to store the output (hash_only, encrypted, plaintext).

    Returns:
        A wrapped client that behaves identically but emits records.
    """
    original_create = client.messages.create

    def instrumented_create(*args: Any, **kwargs: Any) -> Any:
        # Capture pre-call evidence
        model = kwargs.get("model", "unknown")
        messages = kwargs.get("messages", [])
        system = kwargs.get("system")
        temperature = kwargs.get("temperature")
        max_tokens = kwargs.get("max_tokens")
        top_p = kwargs.get("top_p")
        tools = kwargs.get("tools")

        messages_json = json.dumps(messages, sort_keys=True, separators=(",", ":"))
        user_prompt_hash = sha256_hash(messages_json)

        # Anthropic system prompt: separate kwarg (string or list of blocks)
        system_prompt_hash = ""
        if system is not None:
            if isinstance(system, str):
                system_prompt_hash = sha256_hash(system)
            elif isinstance(system, list):
                # List of content blocks — serialize deterministically
                system_json = json.dumps(system, sort_keys=True, separators=(",", ":"))
                system_prompt_hash = sha256_hash(system_json)

        tool_schema_hash = ""
        if tools:
            tools_json = json.dumps(tools, sort_keys=True, separators=(",", ":"))
            tool_schema_hash = sha256_hash(tools_json)

        # Execute the LLM call
        start = time.monotonic()
        response = original_create(*args, **kwargs)
        latency_ms = (time.monotonic() - start) * 1000

        # Capture post-call evidence
        output_text = ""
        finish_reason = ""
        output_tokens = 0
        input_tokens = 0

        # Anthropic response.content is a list of ContentBlock objects
        if hasattr(response, "content") and response.content:
            text_parts = []
            for block in response.content:
                if hasattr(block, "text"):
                    text_parts.append(block.text)
                elif hasattr(block, "type") and block.type == "tool_use":
                    # Include tool_use blocks as JSON evidence
                    tool_data = {
                        "type": "tool_use",
                        "id": getattr(block, "id", ""),
                        "name": getattr(block, "name", ""),
                        "input": getattr(block, "input", {}),
                    }
                    text_parts.append(json.dumps(tool_data, sort_keys=True, separators=(",", ":")))
            output_text = "".join(text_parts)

        # Anthropic uses stop_reason instead of finish_reason
        finish_reason = getattr(response, "stop_reason", "") or ""

        # Anthropic uses input_tokens / output_tokens
        if hasattr(response, "usage") and response.usage:
            input_tokens = getattr(response.usage, "input_tokens", 0) or 0
            output_tokens = getattr(response.usage, "output_tokens", 0) or 0

        output_hash = sha256_hash(output_text)

        # Build DecisionRecord
        rec = DecisionRecord(
            identity=Identity(
                tenant_id=tenant_id,
                subject=subject,
                subject_type="user",
            ),
            model=ModelInfo(
                provider="anthropic",
                name=model,
            ),
            parameters=Parameters(
                temperature=temperature,
                max_tokens=max_tokens,
                top_p=top_p,
                tools_enabled=tools is not None,
            ),
            prompt_context=PromptContext(
                system_prompt_hash=system_prompt_hash,
                user_prompt_hash=user_prompt_hash,
                tool_schema_hash=tool_schema_hash,
                message_count=len(messages),
                total_input_tokens=input_tokens,
            ),
            policy_context=PolicyContext(
                policy_decision=PolicyDecision.LOG_ONLY,
            ),
            output=Output(
                output_hash=output_hash,
                mode=output_mode,
                output_tokens=output_tokens,
                finish_reason=finish_reason,
                latency_ms=latency_ms,
            ),
        )

        # Emit to VAOL server (non-blocking best-effort)
        try:
            receipt = vaol_client.append(rec)
            logger.debug(
                "VAOL record emitted",
                extra={
                    "request_id": rec.request_id,
                    "sequence": receipt.get("sequence_number"),
                },
            )
        except Exception:
            logger.warning("Failed to emit VAOL record", exc_info=True)

        return response

    # Replace the create method
    client.messages.create = instrumented_create
    return client
