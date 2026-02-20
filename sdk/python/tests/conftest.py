"""Shared test fixtures for the VAOL Python SDK test suite."""

from __future__ import annotations

import httpx
import pytest

from vaol.client import AsyncVAOLClient, VAOLClient
from vaol.record import DecisionRecord, Identity, ModelInfo, Output, OutputMode, PromptContext


@pytest.fixture()
def mock_record() -> DecisionRecord:
    """A minimal valid DecisionRecord for testing."""
    return DecisionRecord(
        identity=Identity(tenant_id="test-org", subject="user-1"),
        model=ModelInfo(provider="openai", name="gpt-4o"),
        prompt_context=PromptContext(
            user_prompt_hash="sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ),
        output=Output(
            output_hash="sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            mode=OutputMode.HASH_ONLY,
        ),
    )


@pytest.fixture()
def vaol_client() -> VAOLClient:
    """A VAOL client backed by a mock transport that accepts all requests."""
    transport = httpx.MockTransport(
        lambda req: httpx.Response(
            201,
            json={
                "request_id": "fixture-id",
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
