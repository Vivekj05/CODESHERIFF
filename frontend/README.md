# CodeSheriff Web Dashboard & SaaS Platform

Modern, full-stack Next.js 16 (App Router) web dashboard and SaaS platform for CodeSheriff. Built with React 19, TypeScript, Tailwind CSS v4, and Base UI / shadcn/ui.

This application provides the public product landing page, interactive audit workbench, codebase RAG indexing, rich PR review generation with sequence diagrams, and engineering activity analytics, layered over CodeSheriff's calibrated Bayesian 4-agent security engine.

---

## Key Features & Architecture

### 1. Public Marketing & Product Landing Page (`/`)
* **Interactive Hero**: Features a live simulated PR review card (#148 with calibrated 94.8% Bayesian posterior) demonstrating multi-agent consensus.
* **4-Agent Architecture Showcase**: Clear breakdown of the four specialist witnesses: Structural Taint, Semantic Reasoning, Context Precedent, and Runtime Sandbox.
* **Feature Comparison Matrix**: Benchmarking CodeSheriff against standard LLM code reviewers (hallucination-prone, 80%+ FDR) and traditional static SAST tools (noisy, rule-bound).
* **Call-to-Action**: Direct routing into GitHub OAuth onboarding and dashboard exploration.

### 2. Modern App Shell & Navigation (`(protected)/...`)
* **Responsive `AppSidebar`**: Active route highlighting, repository quota indicators (e.g. 5/10 repos used), and user session profile footer.
* **Unified `AppShell`**: Consistent dark-mode aesthetic with collapsible sidebar and sticky breadcrumb header.
* **Providers**: Integrated TanStack Query (React Query v5) for client cache invalidation, Sonner toast notifications, and `@base-ui/react` TooltipProvider.

### 3. Engineering Analytics & Overview (`/overview`)
* **Contribution Calendar Heatmap** (`ContributionGraph`): 26-week activity heatmap visualizing PR reviews and security audit volume.
* **Activity Overview Trend** (`ActivityOverviewChart`): 6-month interactive gradient area chart built with Recharts, tracking audits, findings, and fixed vulnerabilities over time.
* **Key Metric Cards**: High-level counters for connected repositories, total audits, flagged findings, and calibrated accuracy rate.

### 4. Repository Management & RAG Indexing (`/repositories`)
* **Real-time Filtering**: Search repositories by name or description, and filter by status tabs (*All*, *Active*, *Private*, *Public*).
* **Quota & State Tracking**: Live repository quota counter and toggle for automated PR analysis.
* **One-Click RAG Indexing**: "Index RAG" action triggering semantic codebase chunking and vector store upsert with instant Sonner toast feedback.

### 5. Full-Codebase Semantic RAG System
* **Intelligent AST/Block Chunker** (`src/lib/chunker.ts`): Overlapping semantic chunker with customizable exclusion filters (skips `node_modules`, `.git`, lockfiles, minified bundles, test fixtures).
* **Pinecone & Gemini Embeddings** (`src/lib/pinecone.ts`): Generates 768-dimensional embeddings using Google's `text-embedding-004`. Upserts and queries isolated namespace vectors, with an automatic zero-config in-memory fallback for local offline development.
* **RAG API Routes**:
  * `POST /api/rag/index`: Ingests and vectorizes repository source files.
  * `POST /api/rag/search`: Performs semantic similarity search returning top-K code snippets with metadata.

### 6. Rich Multi-Dimensional AI PR Reviews (`src/lib/gemini-review.ts`)
Synthesizes comprehensive, actionable code reviews using Google Gemini:
* **Executive Summary**: Contextual impact analysis and high-level risk assessment.
* **File-by-File Walkthrough**: Detailed walkthrough of changed modules, functions, and invariants.
* **Interactive Sequence Diagrams**: Dynamic Mermaid.js sequence diagrams rendered in dark-mode SVG with one-click clipboard export (`MermaidViewer`).
* **Key Strengths**: Constructive engineering feedback highlighting well-tested or clean patterns.
* **Actionable Suggestions & Repairs**: Syntax-highlighted diffs proposing verified fixes.
* *(Strictly no fluff, filler, or poems — professional, signal-dense output only).*

### 7. Audit Detail Workbench (`/audits/[id]`)
Four-tab interactive audit inspection interface:
1. **Architecture & Flow**: Mermaid sequence diagram visualizing the change's execution and data flow.
2. **Walkthrough & Summary**: Executive summary and changed file descriptions.
3. **Calibrated Findings**: Bayesian posterior probability, likelihood ratio breakdown across the 4 specialist agents, and evidence breakdown (Detections, Silences, Abstentions).
4. **Suggestions & Repairs**: Code patches with copyable diffs and sandbox verification status.
* Includes direct link to the associated GitHub pull request.

---

## Core Invariants & Rules Encoded

1. **No probability reaches the screen bare**:
   Every posterior renders through `<Posterior>`, which reads `calibration.isProvisional` and marks the probability as an uncalibrated estimate while true. A confident number without empirical backing is the failure this project attacks; the UI does not reproduce it.
2. **Silences and abstentions are distinguished, not collapsed**:
   An agent that ran and found nothing is evidence (SILENCE, LR < 1.0); an agent that could not run is neutral (ABSTENTION, LR = 1.0). Collapsing them into a single "clean" chip would introduce systematic bias.
3. **Session security**:
   The Python FastAPI backend owns OAuth client secrets, exchanges authorization codes, and issues HttpOnly session cookies. Next.js API routes are dedicated to frontend RAG orchestration and dev utilities.

---

## Directory Layout

```
frontend/
├── src/
│   ├── app/
│   │   ├── (protected)/          # Authenticated routes
│   │   │   ├── overview/         # Dashboard with contribution graph & Recharts
│   │   │   ├── repositories/     # Search, filters, RAG indexing
│   │   │   ├── audits/           # Audit list & tabbed detail workbench ([id])
│   │   │   ├── findings/         # Findings drilldown & evidence breakdown
│   │   │   ├── calibration/      # Reliability diagrams, ECE curves, LR tables
│   │   │   └── settings/         # System settings (read-only calibrated thresholds)
│   │   ├── api/
│   │   │   └── rag/              # Codebase RAG endpoints (index, search)
│   │   ├── sign-in/              # GitHub OAuth sign-in flow
│   │   ├── layout.tsx            # Root layout (dark theme, providers, inter font)
│   │   └── page.tsx              # Public marketing landing page
│   ├── components/
│   │   ├── analytics/            # ContributionGraph & ActivityOverviewChart
│   │   ├── reviews/              # MermaidViewer sequence diagram renderer
│   │   ├── ui/                   # Base UI / shadcn design system primitives
│   │   ├── app-shell.tsx         # Sidebar + Header wrapper
│   │   ├── app-sidebar.tsx       # Collapsible navigation sidebar
│   │   ├── posterior.tsx         # Calibrated posterior badge with provisional flag
│   │   └── providers.tsx         # React Query, Tooltip, Sonner Toaster
│   └── lib/
│       ├── api.ts                # FastAPI edge client
│       ├── chunker.ts            # Semantic code chunking utility
│       ├── gemini-review.ts      # Multi-dimensional Gemini PR review generator
│       ├── github.ts             # Octokit API client & mock contribution data
│       ├── pinecone.ts           # Pinecone + Google text-embedding-004 client
│       └── types.ts              # Contract v2.0.0 TypeScript definitions
├── package.json
└── README.md
```

---

## Running Locally

### Prerequisites
* Node.js 20+
* npm or pnpm
* Backend running on `http://localhost:8000` (optional for landing page and RAG mock)

### Commands
```bash
# Install dependencies
npm install

# Run development server (http://localhost:3000)
npm run dev

# Run TypeScript check and production build (strictly enforced gate)
npm run build

# Run ESLint check
npm run lint
```

### Environment Variables (`.env.local`)
```ini
# FastAPI Backend URL (default: http://localhost:8000)
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000

# Google Gemini AI (for RAG embeddings and review generation)
GEMINI_API_KEY=your-gemini-api-key

# Pinecone Vector Database (optional; uses in-memory store if unset)
PINECONE_API_KEY=your-pinecone-api-key
PINECONE_INDEX=codesheriff-codebase

# GitHub Personal Access Token (optional; for higher API rate limits)
GITHUB_TOKEN=your-github-token
```
