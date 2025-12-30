# HieraChainArchitecture

## 📋 Overview

HieraChain is a **multi-language blockchain infrastructure** designed for high-performance enterprise applications. The architecture follows a **layered approach** combining the strengths of three programming languages:

- **Python** (hierachain): Business logic, REST API, high-level abstractions
- **Rust** (hierachain-consensus): High-performance consensus, cryptography
- **Go** (hierachain-engine): High-concurrency networking, transaction processing

---

## 🏗️ High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            Client Applications                                  │
│                    (Web Apps, Mobile, CLI, External Services)                   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                               API Gateway Layer                                 │
│  ┌─────────────────────────────┐      ┌─────────────────────────────────────┐   │
│  │     Python (FastAPI)        │      │          Go (gRPC)                  │   │
│  │     REST API v1/v2          │◄────►│      Arrow IPC Server               │   │
│  │     Blockchain Explorer     │      │      Metrics (Prometheus)           │   │
│  └─────────────────────────────┘      └─────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    ▼                   ▼                   ▼
┌──────────────────────────┐ ┌──────────────────┐ ┌──────────────────────────────┐
│   hierachain (Python)    │ │hierachain-engine │ │  hierachain-consensus (Rust) │
│                          │ │      (Go)        │ │                              │
│  • Core blockchain logic │ │  • Worker Pool   │ │  • Block creation            │
│  • Domain contracts      │ │  • Mempool       │ │  • Hash calculation          │
│  • Hierarchical chains   │ │  • Ordering      │ │  • Merkle tree               │
│  • Security policies     │ │  • P2P Network   │ │  • Digital signatures        │
│  • Storage backends      │ │  • ZMQ Transport │ │  • Consensus algorithms      │
└──────────────────────────┘ └──────────────────┘ └──────────────────────────────┘
            │                         │                         │
            │         PyO3 FFI        │                         │
            └─────────────────────────┼─────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              Data & Storage Layer                               │
│      ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐      │
│      │   SQLite    │   │  In-Memory  │   │ World State │   │ Arrow IPC   │      │
│      │   Backend   │   │   Storage   │   │   Cache     │   │   Files     │      │
│      └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘      │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Project Structure

```
HieraChain-Engine/
├── hierachain/                    # 🐍 Python - Main Framework
│   ├── adapters/                  # External adapters
│   ├── api/                       # REST API (FastAPI)
│   │   ├── v1/                    # API version 1
│   │   ├── v2/                    # API version 2
│   │   ├── server.py              # FastAPI server
│   │   └── blockchain_explorer.py # Explorer endpoints
│   ├── cli/                       # Command-line interface
│   ├── config/                    # Configuration management
│   ├── consensus/                 # Python consensus wrappers
│   │   └── ordering_service.py    # Transaction ordering
│   ├── core/                      # Core blockchain components
│   │   ├── block.py               # Block definitions
│   │   ├── blockchain.py          # Blockchain management
│   │   ├── caching.py             # Performance caching
│   │   ├── domain_contract.py     # Smart contracts
│   │   ├── hybrid_engine.py       # Hybrid processing engine
│   │   ├── parallel_engine.py     # Parallel execution
│   │   └── consensus/             # Consensus implementations
│   ├── domains/                   # Business domain logic
│   ├── error_mitigation/          # Error handling & recovery
│   ├── hierarchical/              # Hierarchical chain system
│   │   ├── channel.py             # Channel management
│   │   ├── main_chain.py          # Main chain logic
│   │   ├── sub_chain.py           # Sub-chain management
│   │   ├── hierarchy_manager.py   # Hierarchy coordination
│   │   └── consensus/             # BFT consensus
│   ├── integration/               # System integrations
│   ├── monitoring/                # Observability & metrics
│   ├── network/                   # Network layer
│   │   ├── zmq_transport.py       # ZeroMQ transport
│   │   └── secure_connection.py   # TLS connections
│   ├── risk_management/           # Risk assessment
│   ├── security/                  # Security & cryptography
│   ├── storage/                   # Data persistence
│   │   ├── memory_storage.py      # In-memory backend
│   │   ├── sql_backend.py         # SQL database
│   │   └── world_state.py         # State management
│   └── units/                     # Utility modules
│
├── hierachain-consensus/          # 🦀 Rust - High-Performance Core
│   ├── lib.rs                     # Library entry point + PyO3 module
│   ├── ffi.rs                     # Foreign Function Interface
│   ├── core/                      # Core components
│   │   ├── block.rs               # Block struct & operations
│   │   ├── blockchain.rs          # Blockchain management
│   │   ├── schemas.rs             # Data schemas
│   │   ├── utils.rs               # Utilities (hashing, Merkle)
│   │   ├── py_wrapper.rs          # Python bindings
│   │   └── consensus/             # Consensus algorithms
│   │       ├── poa.rs             # Proof of Authority
│   │       └── pof.rs             # Proof of Federation
│   ├── consensus/                 # Ordering services
│   │   └── ordering_service.rs    # Transaction ordering
│   ├── hierarchical/              # Hierarchical chains
│   │   ├── main_chain.rs          # Main chain
│   │   ├── sub_chain.rs           # Sub-chains
│   │   ├── bft.rs                 # BFT consensus
│   │   └── hierarchy_manager.rs   # Hierarchy management
│   ├── security/                  # Cryptography
│   │   └── signatures.rs          # Ed25519 signatures
│   ├── error_mitigation/          # Error handling
│   └── utils/                     # Helper functions
│
├── hierachain-engine/             # 🔷 Go - High-Concurrency Layer
│   ├── api/                       # gRPC & Arrow API
│   │   ├── arrow_server.go        # Arrow IPC server
│   │   ├── arrow_handler.go       # Request handlers
│   │   ├── arrow_protocol.go      # Protocol definitions
│   │   └── metrics.go             # Prometheus metrics
│   ├── core/                      # Core processing
│   │   ├── mempool.go             # Transaction mempool
│   │   ├── ordering.go            # Transaction ordering
│   │   └── worker_pool.go         # Worker management
│   ├── data/                      # Data handling
│   │   ├── schema.go              # Arrow schemas
│   │   ├── converter.go           # Data conversion
│   │   └── ipc.go                 # IPC communication
│   ├── network/                   # Networking
│   │   ├── p2p.go                 # Peer-to-peer
│   │   ├── zmq_transport.go       # ZeroMQ transport
│   │   └── propagation.go         # Block propagation
│   ├── integration/               # Integration layer
│   ├── consensus/                 # Go consensus
│   └── monitoring/                # Observability
│
├── cmd/                           # 🚀 Executables
│   ├── hierachain/                # Main CLI application
│   └── arrow-server/              # Standalone Arrow server
│
├── Cargo.toml                     # Rust dependencies
├── go.mod                         # Go dependencies
├── pyproject.toml                 # Python dependencies
└── Makefile                       # Build automation
```

---

## 🔄 Data Flow Architecture

### Transaction Processing Flow

```
                              ┌─────────────────────┐
                              │   Client Request    │
                              │   (REST/gRPC/WS)    │
                              └──────────┬──────────┘
                                         │
                    ┌────────────────────┼────────────────────┐
                    ▼                    ▼                    ▼
         ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
         │  Python FastAPI  │ │   Go gRPC/Arrow  │ │    WebSocket     │
         │    (Validation)  │ │   (High-Speed)   │ │   (Real-time)    │
         └────────┬─────────┘ └────────┬─────────┘ └────────┬─────────┘
                  │                    │                    │
                  └────────────────────┼────────────────────┘
                                       ▼
                          ┌─────────────────────────┐
                          │      Go Mempool         │
                          │ (Transaction Batching)  │
                          └───────────┬─────────────┘
                                      │
                                      ▼
                          ┌─────────────────────────┐
                          │    Go Worker Pool       │
                          │ (Parallel Processing)   │
                          └───────────┬─────────────┘
                                      │
                    ┌─────────────────┴─────────────────┐
                    ▼                                   ▼
         ┌─────────────────────┐           ┌─────────────────────┐
         │   Rust Consensus    │           │   Python Business   │
         │ (Block Creation)    │           │  (Domain Logic)     │
         │ (Hash Calculation)  │           │  (Contracts)        │
         │ (Merkle Root)       │           │  (Validation)       │
         └─────────┬───────────┘           └─────────┬───────────┘
                   │                                 │
                   └─────────────────┬───────────────┘
                                     ▼
                          ┌─────────────────────────┐
                          │    Block Finalization   │
                          │    (Rust Core)          │
                          └───────────┬─────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
         ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
         │  Network Layer   │ │  Storage Layer   │ │    Monitoring    │
         │ (P2P Broadcast)  │ │   (Persist)      │ │   (Metrics)      │
         └──────────────────┘ └──────────────────┘ └──────────────────┘
```

---

## 🔗 Inter-Language Communication

### Python ↔ Rust (PyO3 FFI)

```
┌─────────────────────────────────────────────────────────────────┐
│                        Python Layer                             │
│   from hierachain_consensus import Block, calculate_merkle_root │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                           PyO3 FFI
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Rust Layer                              │
│   #[pyclass] Block                                              │
│   #[pyfunction] calculate_merkle_root                           │
│   #[pymodule] hierachain_consensus                              │
└─────────────────────────────────────────────────────────────────┘
```

### Python ↔ Go (Arrow IPC)

```
┌──────────────────────┐                    ┌──────────────────────┐
│    Python Client     │                    │    Go Server         │
│                      │                    │                      │
│  ┌────────────────┐  │     Arrow IPC      │  ┌────────────────┐  │
│  │  PyArrow       │  │ ←────────────────→ │  │ Apache Arrow   │  │
│  │  Record Batch  │  │   (Zero-Copy)      │  │ Go Library     │  │
│  └────────────────┘  │                    │  └────────────────┘  │
│                      │                    │                      │
│  Port: client        │                    │  Port: 50051         │
└──────────────────────┘                    └──────────────────────┘
```

---

## 🏛️ Hierarchical Chain Architecture

```
                        ┌───────────────────────────────────┐
                        │           MAIN CHAIN              │
                        │    (Global State & Anchoring)     │
                        │                                   │
                        │  • Global consensus               │
                        │  • Cross-chain transactions       │
                        │  • Anchor blocks from sub-chains  │
                        └───────────────────┬───────────────┘
                                            │
           ┌────────────────────────────────┼────────────────────────────────┐
           │                                │                                │
           ▼                                ▼                                ▼
┌──────────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
│     SUB-CHAIN A      │     │     SUB-CHAIN B      │     │     SUB-CHAIN C      │
│   (Organization 1)   │     │   (Organization 2)   │     │   (Organization 3)   │
│                      │     │                      │     │                      │
│ • Local consensus    │     │ • Local consensus    │     │ • Local consensus    │
│ • Private data       │     │ • Private data       │     │ • Private data       │
│ • Domain contracts   │     │ • Domain contracts   │     │ • Domain contracts   │
└──────────────────────┘     └──────────────────────┘     └──────────────────────┘
           │                                │                                │
           │                                │                                │
           ▼                                ▼                                ▼
┌──────────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
│      CHANNELS        │     │      CHANNELS        │     │      CHANNELS        │
│   (Private Comms)    │     │   (Private Comms)    │     │   (Private Comms)    │
└──────────────────────┘     └──────────────────────┘     └──────────────────────┘
```

---

## ⚙️ Consensus Mechanisms

### Supported Algorithms

| Algorithm | Language | Use Case |
|:----------|:---------|:---------|
| **Proof of Authority (PoA)** | Rust | Private networks with trusted validators |
| **Proof of Federation (PoF)** | Rust | Multi-organization permissioned networks |
| **BFT Consensus** | Rust/Python | Byzantine fault-tolerant ordering |
| **Ordering Service** | Rust/Go | Transaction ordering & batching |

### Algorithm Definitions

#### 🔐 Proof of Authority (PoA)

**Proof of Authority** is a consensus mechanism where block validation rights are granted to a set of pre-approved, trusted validators (authorities). Unlike Proof of Work or Proof of Stake, PoA relies on the **reputation and identity** of validators rather than computational power or stake.

**Key Characteristics:**

- **Trusted Validators**: Only authorized nodes can create and validate blocks
- **High Performance**: No mining competition, enabling fast block times
- **Energy Efficient**: Minimal computational overhead
- **Identity-Based**: Validators stake their reputation, not tokens
- **Centralized Trust**: Suitable for private/consortium networks

**Use Cases**: Enterprise blockchains, internal company ledgers, testing environments

---

#### 🤝 Proof of Federation (PoF)

**Proof of Federation** is a consensus mechanism designed for **multi-organization networks** where multiple independent entities must agree on the state of the blockchain. Each organization operates validator nodes, and consensus requires agreement across organizational boundaries.

**Key Characteristics:**

- **Multi-Organization**: Each participating organization runs validator nodes
- **Distributed Trust**: No single organization controls the network
- **Quorum-Based**: Requires a minimum number of organizations to agree
- **Governance**: Organizations can vote on network changes
- **Permissioned**: New organizations must be approved to join

**Use Cases**: Supply chain networks, banking consortiums, cross-company collaborations

---

#### 🛡️ Byzantine Fault Tolerance (BFT)

**Byzantine Fault Tolerance** is a property of distributed systems that enables them to reach consensus even when some nodes fail or act maliciously (Byzantine faults). HieraChain implements **Practical BFT (PBFT)** variants for ordering transactions.

**Key Characteristics:**

- **Fault Tolerance**: Can tolerate up to `f` faulty nodes in a network of `3f + 1` nodes
- **Finality**: Transactions are final once committed (no forks)
- **Deterministic**: All honest nodes reach the same state
- **Message Complexity**: Requires multiple rounds of communication (O(n²))
- **Leader-Based**: Uses a rotating leader for proposal ordering

**Phases (PBFT):**

1. **Pre-Prepare**: Leader proposes a block
2. **Prepare**: Nodes broadcast prepare messages
3. **Commit**: Nodes broadcast commit messages after receiving 2f+1 prepares
4. **Reply**: Block is committed after receiving 2f+1 commits

**Use Cases**: Financial systems, critical infrastructure, high-security applications

---

### Consensus Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Transaction │────►│   Ordering   │────►│   Consensus  │
│   Proposal   │     │   Service    │     │   Protocol   │
└──────────────┘     └──────────────┘     └──────────────┘
                                                  │
                                                  ▼
                                          ┌──────────────┐
                                          │    Block     │
                                          │  Committed   │
                                          └──────────────┘
```

---

## 📊 Performance Architecture

### Optimization Strategies

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          Performance Optimization Layers                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  1. Zero-Copy Data Transfer (Arrow IPC)                                         │
│     └── Eliminates serialization overhead between Python/Go                     │
│                                                                                 │
│  2. Parallel Transaction Processing (Go Worker Pool)                            │
│     └── Concurrent execution with configurable worker count                     │
│                                                                                 │
│  3. Native Cryptography (Rust)                                                  │
│     └── Ed25519 signatures, SHA-256 hashing, Merkle trees                       │
│                                                                                 │
│  4. Batch Operations (Rust)                                                     │
│     └── batch_create_blocks, batch_calculate_hashes                             │
│                                                                                 │
│  5. Transaction Batching (Go Mempool)                                           │
│     └── Groups transactions for efficient processing                            │
│                                                                                 │
│  6. Caching Layer (Python)                                                      │
│     └── In-memory caching for frequently accessed data                          │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Security Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              Security Layers                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐                │
│  │  Transport      │   │  Cryptography   │   │  Access         │                │
│  │  Security       │   │  (Rust)         │   │  Control        │                │
│  │                 │   │                 │   │                 │                │
│  │  • TLS 1.3      │   │  • Ed25519      │   │  • Role-based   │                │
│  │  • mTLS         │   │  • SHA-256      │   │  • Organization │                │
│  │  • ZMQ Curve    │   │  • Merkle Tree  │   │  • Channel      │                │
│  └─────────────────┘   └─────────────────┘   └─────────────────┘                │
│                                                                                 │
│  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐                │
│  │  Private Data   │   │  Secure         │   │  Error          │                │
│  │  Collections    │   │  Connections    │   │  Mitigation     │                │
│  │                 │   │                 │   │                 │                │
│  │  • Encryption   │   │  • Peer Auth    │   │  • Fault        │                │
│  │  • Hash Only    │   │  • Node Verify  │   │    Tolerance    │                │
│  │  • Access Rules │   │  • Key Rotation │   │  • Recovery     │                │
│  └─────────────────┘   └─────────────────┘   └─────────────────┘                │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🌐 Network Architecture

```
                              ┌─────────────────────────┐
                              │    Bootstrap/Seed       │
                              │        Nodes            │
                              └───────────┬─────────────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
                    ▼                     ▼                     ▼
           ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
           │    Peer Node    │   │    Peer Node    │   │    Peer Node    │
           │                 │◄─►│                 │◄─►│                 │
           │  ┌───────────┐  │   │  ┌───────────┐  │   │  ┌───────────┐  │
           │  │ Go Engine │  │   │  │ Go Engine │  │   │  │ Go Engine │  │
           │  │ (P2P/ZMQ) │  │   │  │ (P2P/ZMQ) │  │   │  │ (P2P/ZMQ) │  │
           │  └───────────┘  │   │  └───────────┘  │   │  └───────────┘  │
           │                 │   │                 │   │                 │
           │  ┌───────────┐  │   │  ┌───────────┐  │   │  ┌───────────┐  │
           │  │Python API │  │   │  │Python API │  │   │  │Python API │  │
           │  └───────────┘  │   │  └───────────┘  │   │  └───────────┘  │
           │                 │   │                 │   │                 │
           │  ┌───────────┐  │   │  ┌───────────┐  │   │  ┌───────────┐  │
           │  │Rust Core  │  │   │  │Rust Core  │  │   │  │Rust Core  │  │
           │  └───────────┘  │   │  └───────────┘  │   │  └───────────┘  │
           └─────────────────┘   └─────────────────┘   └─────────────────┘
                    │                     │                     │
                    └─────────────────────┼─────────────────────┘
                                          │
                              ┌───────────┴───────────┐
                              │   Message Protocols   │
                              ├───────────────────────┤
                              │ • ZeroMQ (Fast)       │
                              │ • gRPC (Structured)   │
                              │ • Arrow IPC (Bulk)    │
                              └───────────────────────┘
```

---

## 📈 Monitoring & Observability

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Observability Stack                                   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐          │
│   │    Prometheus    │    │     Grafana      │    │    Logging       │          │
│   │    (Metrics)     │───►│  (Dashboards)    │    │   (Structured)   │          │
│   │                  │    │                  │    │                  │          │
│   │  • tx_count      │    │  • Performance   │    │  • JSON logs     │          │
│   │  • block_time    │    │  • Health        │    │  • Trace IDs     │          │
│   │  • queue_size    │    │  • Alerts        │    │  • Rotation      │          │
│   └────────▲─────────┘    └──────────────────┘    └──────────────────┘          │
│            │                                                                    │
│   ┌────────┴────────────────────────────────────────────────────────────┐       │
│   │                    Go Engine (metrics.go)                           │       │
│   │                    Port: 2112 (/metrics)                            │       │
│   └─────────────────────────────────────────────────────────────────────┘       │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Environment Variables

| Variable | Default | Description |
|:---------|:--------|:------------|
| `HIE_USE_GO_ENGINE` | `false` | Enable Go Engine |
| `HIE_GO_ENGINE_ADDRESS` | `localhost:50051` | gRPC address |
| `HIE_METRICS_ADDRESS` | `:2112` | Prometheus metrics port |

---

## 📚 Related Components

- **hierachain**: Python framework for business logic
- **hierachain-consensus**: Rust library for high-performance consensus
- **hierachain-engine**: Go service for concurrency and networking

---

## 📄 License

Dual licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT).

---

*Last updated: 2024-12-31*
