# Technical Implementation Spec: CodeSheriff RAG Context Agent

**Package:** `context_agent` · **Repo:** `codesheriff-context-agent`  
**Agent ID:** `context.rag` · **Language:** Python 3.12 (`uv`)  
**Purpose:** Analyzes new incoming Pull Requests against a Vector Store (RAG) of previously accepted Pull Requests to detect **Cross-PR Security Regressions** and **Security Control Bypasses**.

---

## 1. Executive Summary & Core Philosophy

In real-world software engineering, vulnerabilities frequently occur when a **new PR accidentally invalidates, bypasses, or breaks security invariants established in past merged PRs**.

The **RAG Context Agent**:
1. Maintains a local vector database of all previously **merged PRs**.
2. Retrieves relevant past PRs when a **new PR** is submitted.
3. Evaluates if the new PR violates security controls, sanitization wrappers, or authorization assumptions established in those past PRs.
4. Operates using **100% Free, Local Open-Source Embeddings** (`bge-small-en-v1.5`) and **ChromaDB**.

---

## 2. System Architecture & Folder Structure

```
codesheriff-context-agent/
├── README.md
├── pyproject.toml
├── .python-version                 # 3.12
├── .env.example
├── src/context_agent/
│   ├── __init__.py
│   ├── contracts.py                # VENDORED — contracts.py (SHA-256 integrity checked)
│   ├── config.py                   # Pydantic settings (ChromaDB path, embedding model)
│   ├── cli.py                      # run | ingest | search | version
│   ├── agent.py                    # ContextAgent.analyze(unit, anchors=None) -> list[Evidence]
│   ├── rag/
│   │   ├── __init__.py
│   │   ├── store.py                # ChromaDB collection client & persistence
│   │   ├── embedder.py             # SentenceTransformers (BAAI/bge-small-en-v1.5)
│   │   └── ingest.py               # Generates Hybrid PR Documents and stores vectors
│   ├── retrieval/
│   │   ├── __init__.py
│   │   └── search.py               # Vector similarity search for Top-K past PRs
│   └── reasoning/
│       ├── __init__.py
│       ├── analyzer.py             # Cross-PR security invariant LLM evaluator
│       └── prompts/
│           └── cross_pr_v1.md      # System prompt comparing New PR vs Past PRs
└── tests/
    ├── conftest.py
    ├── test_embedder.py
    ├── test_store.py
    ├── test_ingest.py
    ├── test_cold_start.py          # Tests PR #1 graceful abstention
    └── test_cross_pr_regression.py # Tests Cross-PR bypass detection
```

---

## 3. Technology Stack ($0 Cost Architecture)

| Component | Selected Tool | Reason / Benefit |
| :--- | :--- | :--- |
| **Language** | Python 3.12 | Fast execution, optimal wheel support for vector DBs |
| **Vector DB** | `chromadb` | **Free, Local**, zero-setup persistent vector database stored on disk |
| **Embedding Engine** | `sentence-transformers` | **100% Free local execution** (runs on CPU or GPU) |
| **Embedding Model** | `BAAI/bge-small-en-v1.5` | ~130MB download size, ultra-fast, handles code + text semantics |
| **LLM Reasoning Engine** | Hosted LLM or Qwen-2.5-Coder | Performs cross-PR logic regression analysis |

---

## 4. Key Implementation Modules

### A. Free Local Embedder (`src/context_agent/rag/embedder.py`)

```python
from sentence_transformers import SentenceTransformer

class LocalEmbedder:
    """Generates 384-dimensional vector embeddings locally for $0 cost."""
    
    def __init__(self, model_name: str = "BAAI/bge-small-en-v1.5") -> None:
        # Downloads model once locally
        self.model = SentenceTransformer(model_name)

    def embed_text(self, text: str) -> list[float]:
        embedding = self.model.encode(text, normalize_embeddings=True)
        return embedding.tolist()
```

---

### B. Vector Store Manager (`src/context_agent/rag/store.py`)

```python
import chromadb
from pathlib import Path

class VectorStore:
    """ChromaDB persistent vector store wrapper."""

    def __init__(self, storage_dir: str = "./.chroma_db") -> None:
        self.client = chromadb.PersistentClient(path=storage_dir)
        self.collection = self.client.get_or_create_collection(
            name="accepted_pull_requests",
            metadata={"hnsw:space": "cosine"}
        )

    def add_pr(self, pr_id: str, hybrid_document: str, embedding: list[float], metadata: dict) -> None:
        self.collection.add(
            ids=[pr_id],
            documents=[hybrid_document],
            embeddings=[embedding],
            metadatas=[metadata]
        )

    def query_similar_prs(self, query_embedding: list[float], top_k: int = 5) -> list[dict]:
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k
        )
        return results
```

---

### C. Hybrid PR Document Ingestion (`src/context_agent/rag/ingest.py`)

When a PR is approved and merged into `main`, it is converted into a **Hybrid PR Document** before embedding:

```python
def create_hybrid_pr_document(pr_data: dict) -> str:
    """Combines PR title, description, modified symbols, and code diff into one searchable document."""
    return f"""
# PR METADATA
PR_ID: {pr_data['pr_id']}
Title: {pr_data['title']}
Description: {pr_data['description']}
Modified Files: {", ".join(pr_data['files'])}
Modified Symbols: {", ".join(pr_data['symbols'])}

# CODE DIFF SUMMARY
{pr_data['code_diff']}
"""
```

---

### D. Primary Agent Workflow & Cold Start Handling (`src/context_agent/agent.py`)

```python
from context_agent.contracts import ChangeUnit, Evidence, EvidenceAbstention
from context_agent.rag.embedder import LocalEmbedder
from context_agent.rag.store import VectorStore

class ContextAgent:
    id: str = "context.rag"
    version: str = "0.1.0"

    def __init__(self, embedder: LocalEmbedder, store: VectorStore) -> None:
        self.embedder = embedder
        self.store = store

    def analyze(self, unit: ChangeUnit, anchors: set[str] | None = None) -> list[Evidence]:
        # Step 1: Cold Start Check (PR #1 handling)
        if self.store.collection.count() == 0:
            return [
                Evidence.abstention(
                    unit_id=unit.unit_id,
                    agent_id=self.id,
                    reason="no_historical_prs",
                    message="Vector database is empty (1st PR in repository)."
                )
            ]

        # Step 2: Generate Vector Embedding of New PR Code
        new_pr_text = f"File: {unit.file}\nSymbol: {unit.symbol}\nDiff:\n{unit.post_src}"
        query_vector = self.embedder.embed_text(new_pr_text)

        # Step 3: Retrieve Top-K Related Past PRs
        past_prs = self.store.query_similar_prs(query_vector, top_k=3)

        if not past_prs or not past_prs["documents"][0]:
            return [
                Evidence.abstention(
                    unit_id=unit.unit_id,
                    agent_id=self.id,
                    reason="no_relevant_past_prs",
                    message="No historically related PRs found in RAG memory."
                )
            ]

        # Step 4: LLM Cross-PR Invariant Analysis
        findings = evaluate_cross_pr_regression(unit, past_prs["documents"][0])
        return findings
```

---

## 5. Cold Start & Edge Case Resolution

| Scenario / Edge Case | Agent Behavior | Impact on CodeSheriff |
| :--- | :--- | :--- |
| **PR #1 (First PR in Repo)** | Vector DB count is 0. Emits `Abstention(no_historical_prs)`. | Zero crash. Static & Semantic agents do primary scan. |
| **PR Merged to `main`** | Background worker embeds merged PR into ChromaDB. | Populates RAG memory for future PRs. |
| **PR #2 (Subsequent PRs)** | Retrieves Top-3 relevant past PRs and checks cross-PR logic. | Detects if PR #2 bypasses security logic from PR #1. |
| **Unrelated New Feature** | Retrieves past PRs, but distance score is low ($\text{cosine similarity} < 0.5$). | Emits `Abstention(no_relevant_past_prs)` to avoid noise. |

---

## 6. Output Contract Example

When the agent detects that a new PR bypasses a security control from a past merged PR, it emits:

```json
[
  {
    "agent_id": "context.rag",
    "agent_version": "0.1.0",
    "unit_id": "pr-220",
    "finding_key": "c9e8d7a6f5b41234",
    "raw_score": 0.92,
    "cwe": "CWE-862",
    "title": "Cross-PR Security Control Bypass",
    "severity": "high",
    "rationale": "PR #220 introduces 'quick_payment()' which calls 'stripe_charge()' directly, bypassing the @require_csrf_token and @rate_limit security controls established in accepted PR #105.",
    "evidence_lines": [14, 15],
    "location": {
      "file": "app/payment.py",
      "start_line": 12,
      "end_line": 16
    }
  }
]
```

---

## 7. Acceptance Criteria

- [x] Uses **100% Free local embedding model** (`BAAI/bge-small-en-v1.5`).
- [x] Uses **local persistent ChromaDB** (zero cloud storage cost).
- [x] Handles **PR #1 Cold Start** via graceful `Abstention(no_historical_prs)`.
- [x] Successfully retrieves related past PRs using hybrid document search.
- [x] Emits strictly validated `Evidence` matching `contracts.py`.
