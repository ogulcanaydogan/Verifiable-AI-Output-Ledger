# VAOL Python SDK

Python client, instrumentation wrappers, and client-side verification for the
**Verifiable AI Output Ledger (VAOL)**.

## Install

```bash
pip install vaol

# With OpenAI auto-instrumentation support
pip install "vaol[openai]"

# Optional providers
pip install "vaol[anthropic]"
pip install "vaol[litellm]"
```

## Quick start

### Manual record creation

```python
from vaol import VAOLClient, DecisionRecord
from vaol.record import Identity, ModelInfo, PromptContext, Output, OutputMode, sha256_hash

client = VAOLClient(server_url="http://localhost:8080", tenant_id="acme-corp")

record = DecisionRecord(
    identity=Identity(tenant_id="acme-corp", subject="user-42"),
    model=ModelInfo(provider="openai", name="gpt-4o"),
    prompt_context=PromptContext(user_prompt_hash=sha256_hash("What is VAOL?")),
    output=Output(
        output_hash=sha256_hash("VAOL is a verifiable AI output ledger."),
        mode=OutputMode.HASH_ONLY,
    ),
)

receipt = client.append(record)
print(f"Appended: seq={receipt['sequence_number']}")
```

### OpenAI auto-instrumentation

```python
from openai import OpenAI
from vaol import VAOLClient, instrument_openai

vaol = VAOLClient(server_url="http://localhost:8080", tenant_id="acme-corp")
openai = OpenAI()

instrument_openai(openai, vaol_client=vaol, tenant_id="acme-corp", subject="user-42")

# Every chat completion now automatically emits a VAOL decision record
response = openai.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

### Anthropic auto-instrumentation

```python
import anthropic
from vaol import VAOLClient, instrument_anthropic

vaol = VAOLClient(server_url="http://localhost:8080", tenant_id="acme-corp")
client = anthropic.Anthropic()

instrument_anthropic(client, vaol_client=vaol, tenant_id="acme-corp", subject="user-42")
response = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=256,
    system="You are a helpful assistant.",
    messages=[{"role": "user", "content": "Summarize this report."}],
)
```

### LiteLLM auto-instrumentation

```python
import litellm
from vaol import VAOLClient, instrument_litellm

vaol = VAOLClient(server_url="http://localhost:8080", tenant_id="acme-corp")
instrument_litellm(vaol_client=vaol, tenant_id="acme-corp", subject="svc:gateway")

response = litellm.completion(
    model="openai/gpt-4o",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

### Async client

```python
import asyncio
from vaol import AsyncVAOLClient

async def main():
    async with AsyncVAOLClient(server_url="http://localhost:8080") as client:
        health = await client.health()
        records = await client.list(tenant_id="acme-corp", limit=10)
        proof = await client.get_proof("request-id-here")
        print(health, records, proof)

asyncio.run(main())
```

## Client-side verification

The SDK includes cryptographic verification that lets auditors verify records
without trusting the server.

### Ed25519 DSSE signature verification

```python
from vaol import verify_dsse_ed25519

# public_key_bytes: raw 32-byte Ed25519 public key
result = verify_dsse_ed25519(envelope_dict, public_key_bytes)
print(result.valid)    # True / False
print(result.summary)  # "all checks passed" or "failed: signature_0"
```

### Merkle inclusion proof verification (RFC 6962)

```python
from vaol import verify_inclusion_proof

result = verify_inclusion_proof(
    leaf_data=canonical_json_bytes,
    leaf_index=42,
    tree_size=100,
    proof_hashes=["sha256:abc...", "sha256:def..."],
    expected_root="sha256:...",
)
print(result.valid)
```

## API reference

### `VAOLClient` / `AsyncVAOLClient`

| Method | Description |
|---|---|
| `append(record)` | Append a DecisionRecord, returns receipt |
| `get(request_id)` | Retrieve a record by ID |
| `list(tenant_id, after, before, limit, cursor)` | List records with filters |
| `get_proof(request_id)` | Get Merkle inclusion proof |
| `verify(envelope, verification_profile=None)` | Server-side DSSE verification (`basic`, `strict`, `fips`) |
| `export(tenant_id, after, before, limit)` | Export audit bundle |
| `health()` | Health check |
| `checkpoint()` | Get latest Merkle checkpoint |

### `verify_dsse_ed25519(envelope, public_key_bytes)`

Client-side Ed25519 DSSE signature verification. Returns `VerifyResult`.

### `verify_inclusion_proof(leaf_data, leaf_index, tree_size, proof_hashes, expected_root)`

Client-side RFC 6962 Merkle inclusion proof verification. Returns `VerifyResult`.

### `DecisionRecord`

Pydantic model for VAOL v1 decision records. Constructed directly or via
`instrument_openai` auto-instrumentation.

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
ruff check vaol/
mypy vaol/
```

## License

Apache 2.0
