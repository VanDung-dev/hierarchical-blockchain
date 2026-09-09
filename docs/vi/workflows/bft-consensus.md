---
title: "Đồng thuận BFT"
description: "Luồng hoạt động đồng thuận chống gian lận (PBFT) để hoàn tất khối trong môi trường có tính đối kháng."
icon: material/shield-key
---

# Đồng thuận BFT

## Tổng quan

Đồng thuận BFT chạy PBFT 3 pha khi hoàn tất khối. Nó yêu cầu `n >= 3f + 1` để chịu được `f` node lỗi hoặc gian lận. Cơ chế này thay thế bước `finalize_block()` trong luồng Gửi Sự kiện khi hệ thống chạy ở chế độ BFT.

Với chi tiết PoA và PoF, xem [Cơ chế Đồng thuận](./consensus_mechanisms.md).

Yêu cầu hệ thống: tối thiểu 4 node để chịu 1 lỗi Byzantine (n=4, f=1: 3x1+1=4).

---

## Biểu đồ luồng: PBFT 3 pha

```mermaid
sequenceDiagram
    autonumber
    participant OS as ⚙️ OrderingService
    participant L as 👑 Nút Trưởng nhóm (Leader Node)
    participant ledger as 🖥️ Trình xác thực 1 (Validator 1)
    participant business as 🖥️ Trình xác thực 2 (Validator 2)
    participant Vf as 🖥️ Trình xác thực f (Validator f)

    OS->>L: Gom cụm sự kiện sẵn sàng → kích hoạt đồng thuận

    rect rgb(0, 0, 0, 0)
        Note over L,Vf: PHA 1 — CHUẨN BỊ TRƯỚC (PRE-PREPARE)
        L->>L: Gán số thứ tự, tạo thông điệp PRE-PREPARE
        L->>ledger: PRE-PREPARE(view, seq, block_digest)
        L->>business: PRE-PREPARE(view, seq, block_digest)
        L->>Vf: PRE-PREPARE(view, seq, block_digest)
    end

    rect rgb(0, 0, 0, 0)
        Note over L,Vf: PHA 2 — CHUẨN BỊ (PREPARE)
        ledger->>ledger: Xác thực PRE-PREPARE, phát tin PREPARE
        ledger->>L: PREPARE(view, seq, digest)
        ledger->>business: PREPARE(view, seq, digest)
        business->>L: PREPARE(view, seq, digest)
        business->>ledger: PREPARE(view, seq, digest)
        Note over L: Thu thập đủ 2f phiếu bầu PREPARE
    end

    rect rgb(0, 0, 0, 0)
        Note over L,Vf: PHA 3 — CAM KẾT (COMMIT)
        L->>ledger: COMMIT(view, seq, digest)
        L->>business: COMMIT(view, seq, digest)
        ledger->>L: COMMIT(view, seq, digest)
        business->>L: COMMIT(view, seq, digest)
        Note over L: Thu thập đủ 2f+1 phiếu bầu COMMIT → hoàn tất
        L->>L: Hoàn tất & ký khối dữ liệu
        L->>OS: Khối dữ liệu đã cam kết → đẩy vào commit_queue
    end
```

---

## Biểu đồ luồng: Thay đổi phiên (View Change)

```mermaid
sequenceDiagram
    autonumber
    participant ledger as 🖥️ Trình xác thực 1
    participant VM as 🔄 BFTViewChangeManager
    participant NEW as 👑 Trưởng nhóm Mới (New Leader)

    Note over ledger: Phát hiện hết hạn kết nối với Leader (không nhận được PRE-PREPARE)

    ledger->>VM: trigger_view_change(current_view, failed_leader)
    VM->>VM: view += 1
    VM->>VM: Phát tin VIEW-CHANGE đến tất cả các trình xác thực
    VM->>VM: Thu thập đủ f+1 phiếu bầu VIEW-CHANGE
    VM->>NEW: Bầu trưởng nhóm mới: Validators[new_view % n]
    NEW->>NEW: Phát tin thông điệp NEW-VIEW
    NEW->>NEW: Bắt đầu lại từ Pha 1 — PRE-PREPARE
```

---

## Các bước chi tiết

| Bước | Mô tả |
|:-----|:------|
| **PRE-PREPARE** | Leader gán số thứ tự và phát thông điệp chứa digest của khối tới mọi validator. |
| **PREPARE** | Mỗi validator kiểm tra PRE-PREPARE, rồi phát phiếu PREPARE của mình. Leader thu đủ 2f phiếu hợp lệ. |
| **COMMIT** | Leader phát COMMIT. Mỗi node thu đủ 2f+1 phiếu COMMIT trước khi xác nhận khối tại chỗ. |
| **View Change** | Nếu leader không phản hồi trong timeout: validator tăng `view` lên 1, bầu `Validators[view % n]` làm leader mới. |

---

## So sánh thuật toán đồng thuận

| Thuật toán | Cơ chế | Khả năng chịu lỗi | Trường hợp dùng |
|:-----------|:-------|:------------------|:-------------------|
| **PoA** | Dựa trên danh tính, node có thẩm quyền ký khối | Danh tiếng validator | Mạng riêng / nội bộ |
| **PoF** | Luân phiên leader, đồng thuận đa số `height % n` | Phân tán niềm tin | Mạng liên doanh / đa tổ chức |
| **BFT** | PBFT 3 pha | Chịu tới `f` node Byzantine trong `3f+1` | Môi trường quan trọng / đối kháng |

---

## Xử lý lỗi

| Tình huống | Hành vi |
|:-----------|:--------|
| Leader không phản hồi | Kích hoạt View Change, bầu leader mới (`Validators[new_view % n]`) |
| Validator gửi digest không hợp lệ | Phiếu bị loại, không tính vào quorum |
| Chia mạng < f node | Giao thức tiếp tục nếu vẫn đủ quorum 2f+1 |
| Chia mạng >= f+1 node | Giao thức tạm dừng tới khi mạng nối lại (ưu tiên an toàn hơn sẵn sàng) |

---

## Lớp và phương thức chính

| Bước | Lớp / Phương thức | Tệp |
|:-----|:--------------|:-----|
| PBFT 3 pha | `BFTConsensus.run_consensus()` | `consensus/bft/consensus.py` |
| PRE-PREPARE | `BFTConsensus._send_pre_prepare()` | `consensus/bft/consensus.py` |
| Thu thập PREPARE | `BFTConsensus._handle_prepare()` | `consensus/bft/consensus.py` |
| Hoàn tất COMMIT | `BFTConsensus._handle_commit()` | `consensus/bft/consensus.py` |
| Thay đổi phiên | `BFTViewChangeManager.trigger_view_change()` | `consensus/bft/consensus.py` |
| Giao thức mạng | `ZmqTransport.send()` / `receive()` | `network/zmq_transport.py` |

---

## Liên quan

- [Cơ chế Đồng thuận](./consensus_mechanisms.md): chi tiết PoA và PoF
- [Gửi Sự kiện](./event-submission.md): BFT thay thế bước `finalize_block()`
- [Giảm thiểu Lỗi & Phục hồi](./error-recovery.md): khôi phục sau lỗi leader ở cấp hệ thống
