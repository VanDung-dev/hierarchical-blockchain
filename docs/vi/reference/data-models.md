---
title: "Data Models"
description: "Describes Event/Block schemas based on hierachain/core/block.py; examples and invariants."
icon: material/database-outline
---

# Data Models

## Mục đích

Trang này định nghĩa các dạng dữ liệu cốt lõi (Event, Block header và Block đầy đủ) để client khác ngôn ngữ có thể đọc và ghi cùng một dữ liệu và các kiểm tra giữ nhất quán.

## Phạm vi

* Dựa trên Arrow schema `EVENT_SCHEMA` trong `hierachain/core/block.py:261`. Đây là Arrow schema duy nhất trong core. Không có `schemas.py` riêng.
* Áp dụng cho core, Sub-Chain/Main Chain và lớp API nơi dữ liệu được serialize.

## Schema chính

### Event

Event là một sự kiện của domain gắn với entity.

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

Ví dụ JSON do API trả về:

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

### Block header và block

Không có `BLOCK_HEADER_SCHEMA` hay `TRANSACTION_SCHEMA` trong code. `Block` là class Python thuần trong `hierachain/core/block.py` với `index`, `timestamp`, `previous_hash`, `merkle_root`, `hash`, `events: pa.Table` (dùng `EVENT_SCHEMA`) và `data`. Các helper gồm `calculate_merkle_root()` và `to_event_list()`. `Block.events` là payload Arrow duy nhất. Block không có bảng transaction riêng và không có cột `zk_proof`.

## Ánh xạ Pydantic (API ledger)

API dùng model Pydantic trong `hierachain/api/ledger/schemas.py` để validate. Chúng ánh xạ tới cấu trúc core:

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

Quy tắc chuyển đổi:

* `EventRequest.details` (dict) trở thành `EVENT_SCHEMA.details` (Map<String, String>).
* `ProofSubmissionRequest` được lưu dạng `Event` trên Main Chain với type `proof_submission`.

## Serialization

* `Block.events` là `pyarrow.Table` trong bộ nhớ. API có thể trả về dạng list dict qua `to_event_list()` hoặc `to_pylist()`.
* `details` luôn là map<string,string>. Input không phải string sẽ được ép sang string.
* `data` là binary. Qua JSON bạn phải mã hóa base64, hoặc bỏ qua nếu không cần.

### Làm việc với dữ liệu binary (field `data`)

Field `data` là `binary` trong Arrow schema. Mã hóa payload nhỏ như PDF, chứng chỉ hoặc object đã serialize sang base64 khi gửi JSON, và giải mã khi nhận.

Ví dụ Python:
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

## Ví dụ thao tác

```python
# Create Block from event list (dict)
blk = Block(index=1, events=[{...}, {...}], previous_hash="<hash>")

# Get event list as dict
events = blk.to_event_list()

# Check chain validity
blockchain.is_chain_valid()
```

## Liên quan

* Core module: [Core](../modules/core.md)
* API Ledger: [API Ledger](api-ledger.md)
