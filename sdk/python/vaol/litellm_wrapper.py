"""LiteLLM module-level wrapper that automatically emits VAOL DecisionRecords.

Usage:
    import litellm
    import vaol

    vaol_client = vaol.VAOLClient("http://localhost:8080")
    vaol.instrument_litellm(vaol_client, tenant_id="my-org")

    # Use litellm.completion exactly as before
    response = litellm.completion(
        model="anthropic/claude-sonnet-4-20250514",
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

logger = logging.getLogger("vaol.litellm_wrapper")


def _parse_provider_model(model_str: str) -> tuple[str, str]:
    """Parse a LiteLLM model string into (provider, model_name).

    Examples:
        "anthropic/claude-sonnet-4-20250514" → ("anthropic", "claude-sonnet-4-20250514")
        "openai/gpt-4o"           → ("openai", "gpt-4o")
        "gpt-4o"                  → ("unknown", "gpt-4o")
    """
    if "/" in model_str:
        parts = model_str.split("/", 1)
        return parts[0], parts[1]
    return "unknown", model_str


def instrument_litellm(
    vaol_client: VAOLClient,
    tenant_id: str,
    subject: str = "sdk-user",
    output_mode: OutputMode = OutputMode.HASH_ONLY,
) -> None:
    """Patch litellm.completion to automatically emit VAOL DecisionRecords.

    Unlike instrument_openai/instrument_anthropic, this patches the module-level
    function instead of a client instance, since LiteLLM uses a functional API.

    Args:
        vaol_client: A VAOL server client.
        tenant_id: The tenant identifier.
        subject: The user/service identifier.
        output_mode: How to store the output (hash_only, encrypted, plaintext).
    """
    import litellm

    # Idempotency guard: don't double-wrap
    if getattr(litellm.completion, "_vaol_instrumented", False) is True:
        return

    original_completion = litellm.completion

    def instrumented_completion(*args: Any, **kwargs: Any) -> Any:
        # Capture pre-call evidence
        model = kwargs.get("model", "unknown")
        messages = kwargs.get("messages", [])
        temperature = kwargs.get("temperature")
        max_tokens = kwargs.get("max_tokens")
        top_p = kwargs.get("top_p")
        tools = kwargs.get("tools")

        provider, model_name = _parse_provider_model(model)

        messages_json = json.dumps(messages, sort_keys=True, separators=(",", ":"))
        user_prompt_hash = sha256_hash(messages_json)

        # System prompt from messages list (OpenAI-style)
        system_prompt_hash = ""
        for msg in messages:
            if msg.get("role") == "system":
                system_prompt_hash = sha256_hash(msg.get("content", ""))
                break

        tool_schema_hash = ""
        if tools:
            tools_json = json.dumps(tools, sort_keys=True, separators=(",", ":"))
            tool_schema_hash = sha256_hash(tools_json)

        # Execute the LLM call
        start = time.monotonic()
        response = original_completion(*args, **kwargs)
        latency_ms = (time.monotonic() - start) * 1000

        # Capture post-call evidence
        # LiteLLM normalizes responses to OpenAI format
        output_text = ""
        finish_reason = ""
        output_tokens = 0
        input_tokens = 0

        if hasattr(response, "choices") and response.choices:
            choice = response.choices[0]
            if hasattr(choice, "message") and choice.message:
                output_text = choice.message.content or ""
            finish_reason = getattr(choice, "finish_reason", "") or ""

        if hasattr(response, "usage") and response.usage:
            output_tokens = getattr(response.usage, "completion_tokens", 0) or 0
            input_tokens = getattr(response.usage, "prompt_tokens", 0) or 0

        output_hash = sha256_hash(output_text)

        # Build DecisionRecord
        rec = DecisionRecord(
            identity=Identity(
                tenant_id=tenant_id,
                subject=subject,
                subject_type="user",
            ),
            model=ModelInfo(
                provider=provider,
                name=model_name,
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

    instrumented_completion._vaol_instrumented = True  # type: ignore[attr-defined]
    litellm.completion = instrumented_completion
