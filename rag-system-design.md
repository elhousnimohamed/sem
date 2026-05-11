# RAG System Design — Company Policy Knowledge Base on AWS

**Version:** 1.0  
**Scope:** Text-only PDF ingestion · Multi-agent retrieval · AWS-native stack  
**Constraint:** All source PDFs contain native text layers (no OCR required)

---

## Table of Contents

1. [Overview & Goals](#1-overview--goals)
2. [Architecture Diagram](#2-architecture-diagram)
3. [Phase 1 — PDF Ingestion & Pre-Processing](#3-phase-1--pdf-ingestion--pre-processing)
4. [Phase 2 — Chunking Strategy](#4-phase-2--chunking-strategy)
5. [Phase 3 — Metadata Schema](#5-phase-3--metadata-schema)
6. [Phase 4 — Embedding & Vector Store](#6-phase-4--embedding--vector-store)
7. [Phase 5 — Retrieval Pipeline](#7-phase-5--retrieval-pipeline)
8. [Phase 6 — Observability & Quality Control](#8-phase-6--observability--quality-control)
9. [AWS Service Summary](#9-aws-service-summary)
10. [Key Design Decisions](#10-key-design-decisions)

---

## 1. Overview & Goals

### Context

This RAG system serves as the **authoritative policy knowledge base** for a multi-agent platform. Source documents include:

- Company-specific cloud security policies (CIS-derived)
- Approved cloud services catalog with conditions of use
- Internal compliance frameworks and exception policies

### Consumers

| Agent | What it needs from RAG |
|---|---|
| Security Agent | Applicable controls, severity, remediation steps |
| Cost Optimizer Agent | Approved service patterns, cost governance rules |
| Architecture Review Agent | Validated services, availability/scalability conditions |

### Design Goals

- **Precision over recall** — agents need accurate, scoped answers, not broad results
- **Source traceability** — every retrieved chunk must cite its document and section
- **Metadata-driven filtering** — each agent queries only its relevant policy scope
- **Text-only pipeline** — no OCR, no image processing, simplified ingestion

---

## 2. Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                          INGESTION LANE                              │
│                                                                      │
│   S3 (raw PDFs)                                                      │
│       │                                                              │
│       └─► EventBridge (s3:ObjectCreated)                             │
│                   │                                                  │
│                   └─► Step Functions (ingestion workflow)            │
│                               │                                      │
│                   ┌───────────┼───────────────┐                      │
│                   │           │               │                      │
│              [Lambda]    [Lambda]        [Lambda]                    │
│            PDF Parser   Structure        Chunker                     │
│           (pdfplumber)  Enrichment    + Atomic Extractor             │
│                   │      (Bedrock)         │                         │
│                   └───────────┴───────────►│                         │
│                                            │                         │
│                               ┌────────────┴──────────┐             │
│                               │                       │             │
│                        [Lambda Embed]           DynamoDB             │
│                     (Titan Embeddings v2)    (chunk registry,        │
│                               │              version tracking)       │
│                               │                                      │
│                    OpenSearch Serverless                             │
│                    ┌──────────────────────┐                          │
│                    │  index: chunks-t1-t2 │                          │
│                    │  index: chunks-t3    │                          │
│                    └──────────────────────┘                          │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                          RETRIEVAL LANE                              │
│                                                                      │
│   Agent query                                                        │
│       │                                                              │
│       └─► API Gateway ──► Lambda (retrieval orchestrator)            │
│                                   │                                  │
│                          Query Decomposition                         │
│                          (Bedrock Claude Haiku)                      │
│                                   │                                  │
│                       Metadata Pre-Filtering                         │
│                       (OpenSearch bool filter)                       │
│                                   │                                  │
│                    ┌──────────────┴─────────────┐                    │
│                    │                            │                    │
│             kNN Semantic                   BM25 Keyword              │
│              Search                           Search                 │
│                    │                            │                    │
│                    └──────────────┬─────────────┘                    │
│                                   │                                  │
│                      RRF Merge (Reciprocal Rank Fusion)              │
│                                   │                                  │
│                          Cohere Rerank v3                            │
│                          (Bedrock hosted)                            │
│                                   │                                  │
│               Top-K chunks + provenance metadata                     │
│                          → Calling agent                             │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Phase 1 — PDF Ingestion & Pre-Processing

### Trigger & Workflow

All PDFs are stored in S3 with a structured prefix:

```
s3://company-policy-kb/
    raw/policies/        ← drop zone for new PDFs
    raw/service-catalog/ ← approved services documents
    processed/           ← structured JSON output
    archived/            ← versioned previous PDFs
```

An **EventBridge rule** fires on `s3:ObjectCreated` under `raw/`. It triggers a **Step Functions** workflow that orchestrates the three Lambda stages below.

### Stage 1 — PDF Parsing (Lambda: `fn-pdf-parser`)

Since all PDFs contain native text layers, **pdfplumber** is used exclusively. No Textract dependency.

**pdfplumber advantages for text PDFs:**
- Preserves text layout, indentation, and column structure
- Extracts tables natively as structured data (list of rows)
- Page-level granularity with bounding boxes
- Zero per-page AWS cost (runs in Lambda, no managed service call)

**Lambda configuration:**

| Setting | Value |
|---|---|
| Runtime | Python 3.12 |
| Memory | 1024 MB |
| Timeout | 5 minutes |
| Layer | pdfplumber + dependencies (~45 MB) |
| Trigger | Step Functions task |

**Output per page:**

```json
{
  "page_number": 3,
  "raw_text": "1.2 Ensure MFA is enabled...",
  "tables": [
    {
      "rows": [["Control", "Severity", "Service"], ["1.2", "HIGH", "IAM"]]
    }
  ],
  "has_toc": false
}
```

### Stage 2 — Structure Enrichment (Lambda: `fn-structure-enricher`)

A Bedrock Claude Haiku call analyzes the raw text and extracts document structure. This is a **fast, cheap classification call** — not a full generation task.

**System prompt (condensed):**

```
You are a document structure parser. Given raw text from a policy PDF page,
extract the hierarchical section structure as JSON. Identify:
- Section IDs (e.g., 1, 1.2, 1.2.3)
- Section titles
- Nesting level (1=top, 2=sub, 3=leaf)
- Control metadata if present: severity, applicable services, conditions
- Cross-references to other sections
Return ONLY valid JSON. No explanation.
```

**Output — structured document JSON:**

```json
{
  "document_id": "cis-aws-v3.0",
  "document_type": "policy",
  "policy_framework": "CIS",
  "cloud_provider": "AWS",
  "version": "3.0",
  "effective_date": "2024-01-15",
  "source_s3_key": "raw/policies/cis-aws-v3.0.pdf",
  "sections": [
    {
      "section_id": "1",
      "title": "Identity and Access Management",
      "level": 1,
      "content": "This section covers...",
      "subsections": [
        {
          "section_id": "1.2",
          "title": "Ensure MFA is Enabled for All IAM Users with Console Access",
          "level": 2,
          "content": "Multi-factor authentication adds a layer of...",
          "severity": "HIGH",
          "control_type": "preventive",
          "applicable_services": ["IAM"],
          "applicable_environments": ["production", "staging"],
          "conditions": ["console-access", "human-identity"],
          "cross_references": ["1.1", "2.3"],
          "tables": []
        }
      ]
    }
  ]
}
```

This JSON is saved to `s3://company-policy-kb/processed/` and passed to Stage 3.

### Stage 3 — Version Management

Before chunking, **DynamoDB** records the new document version:

```
Table: policy-document-registry
PK: document_id        (e.g., "cis-aws-v3.0")
SK: version            (e.g., "3.0")
Attributes:
  - s3_processed_key
  - effective_date
  - ingested_at
  - status            (active | superseded)
  - chunk_count
```

If a document with the same `document_id` already exists, its status is set to `superseded` before the new version is indexed. Old chunks in OpenSearch are soft-deleted via a metadata flag (`active: false`) — not physically removed, preserving audit history.

---

## 4. Phase 2 — Chunking Strategy

> **This is the most critical design decision in the entire system.**
> Policy documents are hierarchical and conditional. Naive fixed-size chunking destroys the context that makes a policy meaningful.

### Three-Tier Architecture

```
Structured JSON Document
        │
        ├──── Tier 1 (T1): Document Summary        1 chunk per document
        ├──── Tier 2 (T2): Section Chunks          Primary retrieval unit
        └──── Tier 3 (T3): Atomic Fact Chunks      Precision retrieval
```

All three tiers live in the same vector index, differentiated by the `chunk_tier` metadata field.

---

### Tier 1 — Document Summary Chunk

**One chunk per document.** Generated by a Bedrock Claude call summarizing the document's scope, coverage, and key themes.

| Property | Value |
|---|---|
| Size | ~400–500 tokens |
| Count | 1 per document |
| Purpose | Query routing — helps the retrieval layer identify which document to search first |
| Generated by | Bedrock Claude Haiku (summarization prompt) |

**Chunk format:**

```
[CHUNK_TYPE]   T1 - Document Summary
[DOCUMENT]     CIS AWS Foundations Benchmark v3.0
[SCOPE]        IAM, S3, EC2, RDS, CloudTrail, Networking
[PURPOSE]      Defines security controls and hardening guidelines for AWS environments.
               Covers identity management, data protection, logging, and network security.
               Applicable to all production and staging AWS accounts.
[KEY_THEMES]   MFA enforcement, encryption at rest, access key rotation,
               public access restrictions, audit logging requirements
[POLICY_COUNT] 58 controls across 6 domains
```

---

### Tier 2 — Section-Level Semantic Chunks (Primary)

**One chunk per leaf-level section** (i.e., the lowest level of nesting that contains actionable content — typically a single control or policy rule).

| Property | Value |
|---|---|
| Target size | 400–600 tokens |
| Overlap | Structured overlap only (see below) |
| Boundary rule | Never split mid-sentence or mid-table |
| Count | 10–150 per document depending on size |

**Structured overlap vs. sliding window:**

Do NOT use a sliding window overlap. Instead, every T2 chunk includes:
- Its own content
- The parent section title and ID as a breadcrumb header
- The first sentence of the next sibling section as a context tail (if relevant)

This preserves hierarchical context without arbitrary text duplication.

**Chunk anatomy — strictly enforce this format:**

```
[BREADCRUMB]    CIS AWS v3.0 > Section 1: IAM > Control 1.2
[TITLE]         1.2 — Ensure MFA is Enabled for All IAM Users with Console Access
[SEVERITY]      HIGH | Control Type: Preventive | Services: IAM
[CONDITIONS]    Environments: Production, Staging | Scope: Human identities with console access
────────────────────────────────────────────────────────────
<section body content — description, rationale, remediation steps>
────────────────────────────────────────────────────────────
[REFERENCES]    See also: Control 1.1 (Root Account MFA), Control 2.3 (Access Key Policy)
[SOURCE]        CIS AWS Foundations Benchmark v3.0, Section 1.2, Page 14
```

> **Why embed metadata into the chunk text itself?**
> The embedding model encodes the full chunk text. If metadata (severity, service, conditions) only exists in the OpenSearch document fields and not in the text, semantic similarity searches will miss context. Including them in both places ensures the vector captures the full semantic meaning AND the metadata filter can apply hard constraints.

---

### Tier 3 — Atomic Fact Chunks

**Discrete, self-contained policy facts** extracted from each T2 chunk by an LLM during ingestion. Each atomic chunk expresses a single rule, condition, or constraint.

| Property | Value |
|---|---|
| Target size | 50–120 tokens |
| Format | Subject → Condition → Rule |
| Generated by | Bedrock Claude Haiku (extraction prompt) |
| Count | 3–10 per T2 chunk |

**Extraction prompt (condensed):**

```
Given this policy section, extract all discrete, self-contained rules as atomic facts.
Each fact must be independently understandable without reading the full section.
Always append: Source: <document_id>, Section <section_id>
Return a JSON array of strings. One string per fact.
```

**Examples of atomic fact chunks:**

```
"S3 buckets in production must have Block Public Access enabled on all 
 four settings. Exceptions require CISO approval. 
 Source: CIS AWS v3.0, Section 2.1.2"

"Root account API keys are prohibited in all environments regardless 
 of use case. Source: CIS AWS v3.0, Section 1.4"

"EC2 instances are approved for production use only when deployed within 
 a VPC with private subnets. Source: Internal Cloud Policy v2, Section 3.4"

"Transfer Acceleration on S3 is conditionally approved for cross-region 
 data transfer workloads exceeding 1 GB. Requires tagging with 
 cost-center and owner. Source: Approved Services Catalog v1.1, Page 8"
```

---

### Chunking Rules Summary

| Rule | Description |
|---|---|
| No mid-sentence splits | Chunk boundaries always at sentence or paragraph end |
| No mid-table splits | Tables are always kept whole in a single chunk. If a table exceeds 600 tokens, split by rows and duplicate the header row |
| Breadcrumb always included | Every T2 chunk header includes the full section hierarchy |
| Metadata in text AND fields | Key metadata embedded in chunk text body, not only in metadata fields |
| Cross-references preserved | Always include `[REFERENCES]` block even if empty |
| Source always appended | Every T3 atomic fact ends with `Source: <doc_id>, <section>` |

---

## 5. Phase 3 — Metadata Schema

Every chunk (T1, T2, T3) receives a full metadata envelope stored in OpenSearch alongside its vector. This schema drives **metadata pre-filtering** — the most important lever for retrieval precision.

```json
{
  "chunk_id": "cis-aws-v3.0_s1.2_t2_001",
  "chunk_tier": "T2",
  "active": true,

  "document_id": "cis-aws-v3.0",
  "document_type": "policy",
  "policy_framework": "CIS",
  "document_version": "3.0",
  "effective_date": "2024-01-15",
  "source_s3_key": "raw/policies/cis-aws-v3.0.pdf",
  "page_number": 14,

  "section_id": "1.2",
  "section_title": "Ensure MFA is Enabled for All IAM Users with Console Access",
  "parent_section_id": "1",
  "parent_section_title": "Identity and Access Management",
  "nesting_level": 2,

  "severity": "HIGH",
  "control_type": "preventive",
  "cloud_provider": "AWS",
  "applicable_services": ["IAM"],
  "applicable_environments": ["production", "staging"],
  "conditions": ["console-access", "human-identity"],
  "cross_references": ["1.1", "2.3"],

  "agent_scope": ["security", "compliance"],

  "ingested_at": "2024-02-01T10:30:00Z",
  "embedding_model": "amazon.titan-embed-text-v2"
}
```

### `agent_scope` Classification

The `agent_scope` field is assigned during ingestion by a Bedrock classification step. It controls which agents receive which chunks during pre-filtering.

| Value | Description |
|---|---|
| `security` | Controls, severity, remediation steps, prohibited configurations |
| `compliance` | Audit requirements, regulatory mappings, exception procedures |
| `cost` | Approved instance types, reserved capacity rules, cost tagging requirements |
| `architecture` | Availability requirements, scaling conditions, approved service patterns |
| `catalog` | Approved/prohibited services and their conditions of use |

A chunk can belong to multiple scopes (e.g., `["security", "compliance"]`).

---

## 6. Phase 4 — Embedding & Vector Store

### Embedding Model

**Amazon Titan Embeddings v2** is used for all chunk tiers.

| Property | Value |
|---|---|
| Model ID | `amazon.titan-embed-text-v2:0` |
| Output dimensions | 1024 |
| Max input tokens | 8192 |
| Invocation | Bedrock `InvokeModel` API |
| Cost | No egress, billed per token |

Titan v2 fits all three tiers comfortably within its context window. No need for a second embedding model.

### Vector Store — OpenSearch Serverless

**Why OpenSearch Serverless over alternatives:**

| Capability | OpenSearch Serverless | Aurora pgvector | Bedrock KB native |
|---|---|---|---|
| Hybrid search (kNN + BM25) | ✅ Native | ❌ Semantic only | ❌ Semantic only |
| Metadata pre-filtering | ✅ Full bool filter | ✅ SQL WHERE | Limited |
| Fully managed | ✅ Serverless | ✅ | ✅ |
| AWS-native IAM | ✅ | ✅ | ✅ |
| Cost model | OCU/hr (pay per use) | Instance-based | Abstracted |

Hybrid search (keyword + semantic) is **non-negotiable** for policy documents. Terms like `"CIS Control 1.3"`, `"Block Public Access"`, or `"Transfer Acceleration"` must be matchable by exact keyword, not just semantic similarity.

### Index Design

Two OpenSearch Serverless collections:

```
Collection: policy-knowledge-base
│
├── Index: policy-chunks-main         (T1 summary + T2 section chunks)
│   Mapping:
│   ├── embedding         knn_vector(1024), engine: faiss, method: hnsw
│   ├── content           text, analyzer: english (BM25 indexed)
│   ├── chunk_id          keyword
│   ├── chunk_tier        keyword
│   ├── document_id       keyword
│   ├── severity          keyword
│   ├── agent_scope       keyword (array)
│   ├── applicable_services  keyword (array)
│   ├── applicable_environments  keyword (array)
│   └── active            boolean
│
└── Index: policy-chunks-atomic       (T3 atomic fact chunks)
    Mapping: (same structure, separate index for independent tuning)
```

### kNN Index Configuration

```json
{
  "settings": {
    "index": {
      "knn": true,
      "knn.algo_param.ef_search": 512
    }
  },
  "mappings": {
    "properties": {
      "embedding": {
        "type": "knn_vector",
        "dimension": 1024,
        "method": {
          "name": "hnsw",
          "engine": "faiss",
          "parameters": {
            "m": 48,
            "ef_construction": 256
          }
        }
      },
      "content": {
        "type": "text",
        "analyzer": "english"
      }
    }
  }
}
```

Higher `m` (48) and `ef_construction` (256) values favor **recall quality** over index build speed. For a policy corpus (small, rarely updated, high precision required), this tradeoff is correct.

---

## 7. Phase 5 — Retrieval Pipeline

A retrieval request passes through four sequential stages. Total target latency: **< 800ms end-to-end**.

```
Agent query
    │
    ▼  Stage 1 — Query Decomposition         (~100ms, Bedrock Haiku)
    │
    ▼  Stage 2 — Metadata Pre-Filtering      (~10ms, OpenSearch filter)
    │
    ▼  Stage 3 — Hybrid Search + RRF         (~200ms, OpenSearch kNN + BM25)
    │
    ▼  Stage 4 — Reranking                   (~300ms, Cohere Rerank v3)
    │
    ▼  Final context (Top-K chunks + sources)
```

---

### Stage 1 — Query Decomposition

**Lambda `fn-query-decomposer`** calls Bedrock Claude Haiku to transform the raw agent query into a structured retrieval request.

**Input:**
```
"Is S3 Transfer Acceleration approved for production workloads?"
```

**Output:**
```json
{
  "semantic_query": "S3 Transfer Acceleration production environment approval conditions",
  "keyword_boost_terms": ["S3", "Transfer Acceleration", "production"],
  "metadata_filters": {
    "applicable_services": ["S3"],
    "applicable_environments": ["production"],
    "agent_scope": ["security", "catalog"],
    "active": true
  },
  "target_tiers": ["T2", "T3"],
  "top_k": 12
}
```

The decomposition extracts:
- A rephrased semantic query optimized for embedding similarity
- Explicit keyword terms for BM25 boosting
- Hard metadata filters inferred from the query context
- Which chunk tiers to search (T1 is only used for routing, not for agent responses)

---

### Stage 2 — Metadata Pre-Filtering

**Hard filters are applied in OpenSearch before vector search begins.** This narrows the search space to relevant chunks only, improving both speed and precision.

```json
{
  "bool": {
    "must": [
      { "term": { "active": true } },
      { "terms": { "agent_scope": ["security", "catalog"] } }
    ],
    "filter": [
      { "terms": { "applicable_services": ["S3"] } }
    ],
    "should": [
      { "term": { "applicable_environments": "production" } }
    ]
  }
}
```

`must` clauses are hard constraints. `filter` clauses narrow the candidate set without scoring. `should` clauses boost relevance but don't exclude.

---

### Stage 3 — Hybrid Search with RRF

Two searches run in parallel against the pre-filtered candidate set:

**kNN semantic search:**
```json
{
  "knn": {
    "embedding": {
      "vector": [<query_embedding_vector>],
      "k": 15
    }
  }
}
```

**BM25 keyword search:**
```json
{
  "multi_match": {
    "query": "S3 Transfer Acceleration production",
    "fields": ["content^2", "section_title^3"],
    "type": "best_fields",
    "boost": 1.5
  }
}
```

**Reciprocal Rank Fusion (RRF) merge:**

```
RRF score = Σ  1 / (k + rank_i)
            i

where k = 60 (standard), rank_i = position in each result list
```

RRF is rank-based, not score-based. This avoids the need to normalize between cosine similarity and BM25 TF-IDF scores, which have incompatible scales.

The merged list produces a unified ranking of up to 15 candidates.

---

### Stage 4 — Reranking

**Cohere Rerank v3** (available via Amazon Bedrock) performs a cross-encoder reranking pass. Unlike embedding similarity (which encodes query and chunks independently), a cross-encoder processes the query-chunk pair jointly, yielding significantly higher precision.

```
Input:  Original query + Top 15 candidate chunks
Model:  cohere.rerank-v3-5:0 (Bedrock)
Output: Top 5–7 chunks with relevance scores (0.0–1.0)
```

After reranking:
- Deduplicate near-identical chunks (cosine similarity > 0.95 between chunks → keep higher-ranked)
- Attach provenance to each chunk before returning

**Final output structure:**

```json
{
  "retrieved_chunks": [
    {
      "chunk_id": "approved-svc-catalog-v1.1_s4.2_t2_001",
      "relevance_score": 0.96,
      "chunk_tier": "T2",
      "source": "Approved Services Catalog v1.1, Section 4.2, Page 8",
      "document_id": "approved-svc-catalog-v1.1",
      "section_id": "4.2",
      "content": "[BREADCRUMB] ... [TITLE] S3 Transfer Acceleration — Conditional Approval ..."
    },
    {
      "chunk_id": "approved-svc-catalog-v1.1_s4.2_t3_003",
      "relevance_score": 0.91,
      "chunk_tier": "T3",
      "source": "Approved Services Catalog v1.1, Section 4.2",
      "content": "Transfer Acceleration on S3 is conditionally approved for cross-region transfer workloads exceeding 1 GB. Source: Approved Services Catalog v1.1, Section 4.2"
    }
  ],
  "query_metadata": {
    "latency_ms": 612,
    "top1_score": 0.96,
    "chunks_after_prefilter": 34,
    "chunks_after_rerank": 5
  }
}
```

---

## 8. Phase 6 — Observability & Quality Control

RAG quality degrades silently. Active monitoring is essential.

### CloudWatch Metrics (custom namespace: `PolicyKB/Retrieval`)

| Metric | Description | Alarm Threshold |
|---|---|---|
| `RetrievalLatencyMs` | End-to-end retrieval time | > 1000ms (p95) |
| `Top1RelevanceScore` | Reranker score of best chunk | < 0.70 |
| `ChunksAfterPrefilter` | Candidates surviving metadata filter | = 0 (metadata gap) |
| `ChunksAfterRerank` | Final chunks returned | = 0 (full miss) |
| `QueryDecompositionErrors` | Haiku call failures | > 0 |
| `EmbeddingErrors` | Titan embedding failures | > 0 |

### X-Ray Tracing

Enable X-Ray across the retrieval Lambda chain. Each stage emits a subsegment:

```
Trace: RetrievalRequest
  ├── Segment: QueryDecomposition    (Haiku call duration)
  ├── Segment: PreFilter             (OpenSearch filter duration)
  ├── Segment: HybridSearch          (kNN + BM25 duration)
  └── Segment: Reranking             (Cohere Rerank duration)
```

### Feedback Loop

When a specialized agent produces a finding or response, log the `chunk_ids` used. This builds a ground-truth dataset over time.

```
DynamoDB Table: retrieval-audit-log
  - request_id
  - requesting_agent        (security | cost | arch-review)
  - query
  - returned_chunk_ids[]
  - top1_relevance_score
  - agent_used_chunks[]     (which chunks were actually cited in the agent output)
  - timestamp
```

The delta between `returned_chunk_ids` and `agent_used_chunks` identifies retrieval noise — chunks that were retrieved but not useful. This data drives chunking and metadata improvements.

### Ingestion Quality Checks (Step Functions)

Each ingestion workflow includes a validation step before indexing:

| Check | Failure action |
|---|---|
| T2 chunk count > 0 | Abort, alert SNS |
| Average T2 chunk size within 300–700 tokens | Log warning, continue |
| All chunks have `agent_scope` assigned | Abort, alert SNS |
| Document version not already active | Archive previous version first |
| Embedding dimension = 1024 | Abort, mismatch in model |

---

## 9. AWS Service Summary

| Component | AWS Service | Purpose |
|---|---|---|
| PDF Storage | S3 + versioning | Raw PDFs, processed JSON, archived versions |
| Ingestion trigger | EventBridge | Fire on S3 PutObject |
| Workflow orchestration | Step Functions | Ingestion pipeline with retries and branching |
| PDF parsing | Lambda + pdfplumber | Text extraction from native text PDFs |
| Structure enrichment | Lambda + Bedrock Claude Haiku | Section hierarchy and metadata extraction |
| Atomic fact extraction | Lambda + Bedrock Claude Haiku | T3 chunk generation |
| Embedding | Bedrock Titan Embeddings v2 | Vector generation for all chunk tiers |
| Vector store | OpenSearch Serverless | Hybrid search (kNN + BM25) with metadata filtering |
| Chunk registry | DynamoDB | Version tracking, chunk ID mapping, audit log |
| Query decomposition | Lambda + Bedrock Claude Haiku | Structured retrieval request generation |
| Reranking | Bedrock Cohere Rerank v3 | Cross-encoder precision pass |
| API entry point | API Gateway | Agent-facing retrieval endpoint |
| Observability | CloudWatch + X-Ray | Metrics, alarms, distributed tracing |
| Alerting | SNS | Ingestion failures, quality alarms |

---

## 10. Key Design Decisions

### Why pdfplumber over Amazon Textract?

All source PDFs contain native text layers. Textract is purpose-built for OCR on scanned or image-based documents. Using it for native text PDFs adds unnecessary cost (~$0.0015/page), latency (async job model), and complexity. pdfplumber runs entirely within Lambda at no additional cost and produces higher-fidelity output for structured text documents.

### Why three chunk tiers?

A single chunking approach cannot serve all retrieval needs simultaneously:
- T1 (summary) enables fast document routing without searching the full corpus
- T2 (section) provides the contextual richness that specialized agents need to reason about a policy
- T3 (atomic) provides the precision that security or compliance agents need to match a single rule against an infrastructure finding

### Why hybrid search instead of pure semantic?

Policy documents contain precise technical terminology: service names, control IDs, configuration parameter names. Pure semantic (kNN) search encodes meaning but can rank a semantically similar but differently-named control higher than an exact match. BM25 keyword search anchors retrieval on exact terms. RRF combines both without score normalization complexity.

### Why metadata pre-filtering before vector search?

Without pre-filtering, a security agent query might surface cost optimization policies, diluting the result set. Pre-filtering narrows the candidate pool to agent-relevant chunks first, then applies semantic search within that pool. This yields significantly higher precision and lower latency, especially as the corpus grows.

### Why Cohere Rerank instead of relying on kNN scores?

Embedding similarity computes query and chunk vectors independently. A cross-encoder (reranker) processes the query-chunk pair jointly, capturing nuanced relevance signals that bi-encoder embeddings miss. For a policy knowledge base where precision is critical — a misretrieved policy could produce a false compliance finding — the additional reranking latency (~300ms) is a worthwhile tradeoff.

---

*Document generated: May 2026*  
*Architecture valid for AWS regions with Bedrock and OpenSearch Serverless availability*
