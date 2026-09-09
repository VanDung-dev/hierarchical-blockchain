---
title: "Data Models"
description: "Describes Event/Block schemas based on hierachain/core/block.py; examples and invariants."
icon: material/database-outline
---

# Data Models

## Purpose

This page defines the core data shapes (Event, Block header, and full Block) so clients in different languages can read and write the same data and checks stay consistent.

## Scope

* Based on Arrow schema `EVENT_SCHEMA` in `hierachain/core/block.py:261`. This is the only Arrow schema in core. There is no separate `schemas.py`.
* Applies to core, Sub-Chain/Main Chain, and the API layer where data is serialized.

## Main schemas

### Event

An event is a domain fact about an entity.

```python
EVENT_SCHEMA = schema([
  ('entity_id', string),          # Entity ID
  ('event', string),              # Event type
  ('timestamp', float64),         # epoch seconds (float)
  ('details', map<string,string>),# metadata key->string (On-chain)
  ('details_cid', string),        # IPFS CID (Off-chain reference)
  ('details_nonce', string),      # Encryption nonce
  ('data', binary),               # optional binary payload
])
```

Example JSON as returned by the API:

```json
{
  "entity_id": "PROD-001",
  "event": "production_complete",
  "timestamp": 1703088000.0,
  "details": null,
  "details_cid": "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco",
  "details_nonce": "a1b2c3d4e5f6...",
  "data": null
}
```

### Block header and block

There is no `BLOCK_HEADER_SCHEMA` or `TRANSACTION_SCHEMA` in code. `Block` is a plain Python class in `hierachain/core/block.py` with `index`, `timestamp`, `previous_hash`, `merkle_root`, `hash`, `events: pa.Table` (using `EVENT_SCHEMA`), and `data`. Helpers include `calculate_merkle_root()` and `to_event_list()`. `Block.events` is the only Arrow payload. The block has no separate transaction table and no `zk_proof` column.

## Pydantic mapping (API ledger)

The API uses Pydantic models in `hierachain/api/ledger/schemas.py` for validation. They map to the core structures:

```python
class EventRequest(BaseModel):
    entity_id: str
    event_type: str
    details: dict[str, Any] | None
    details_cid: str | None
    details_nonce: str | None
    details_metadata: dict[str, Any] | None

class ProofSubmissionRequest(BaseModel):
    sub_chain_name: str | None
    proof_hash: str | None
    metadata: dict[str, Any] | None
```

**Conversion rules:**

* `EventRequest.details` (dict) becomes `EVENT_SCHEMA.details` (Map<String, String>).
* `ProofSubmissionRequest` is stored as an `Event` on Main Chain with type `proof_submission`.

## Serialization

* `Block.events` is a `pyarrow.Table` in memory. The API can return it as a list of dicts via `to_event_list()` or `to_pylist()`.
* `details` is always map<string,string>. Non-string inputs are coerced to strings.
* `data` is binary. Over JSON you must base64-encode it, or omit it.

### Working with binary data (`data` field)

The `data` field is `binary` in the Arrow schema. Encode small payloads such as PDFs, certificates, or serialized objects to base64 when sending JSON, and decode on receipt.

**Python example:**
```python
import base64

# 1. Preparing binary data to send via Event
raw_data = b"Enterprise visual quality report content"
encoded_data = base64.b64encode(raw_data).decode('utf-8')

event_payload = {
    "entity_id": "PROD-001",
    "event": "quality_inspection",
    "data": encoded_data
}

# 2. Reading and decoding binary data from a Block or Event Response
received_encoded_data = event_payload["data"]
decoded_data = base64.b64decode(received_encoded_data)
print(decoded_data.decode('utf-8'))  # "Enterprise visual quality report content"
```

## Example operations

```python
# Create Block from event list (dict)
blk = Block(index=1, events=[{...}, {...}], previous_hash="<hash>")

# Get event list as dict
events = blk.to_event_list()

# Check chain validity
blockchain.is_chain_valid()
```

## Related

* Core module: [Core](../modules/core.md)
* API Ledger: [API Ledger](api-ledger.md)
