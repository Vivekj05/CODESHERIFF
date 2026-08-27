# Dashboard

Next.js (App Router) + TypeScript, Tailwind, shadcn/ui, Recharts. Not yet built - PLAN.md v1.0.

**This is a rendering layer only.** No business logic, no database access, no detection logic in
TypeScript. The backend must be Python because tree-sitter, scikit-learn and Wasmtime bindings
have no viable JS equivalent (PROJECT_CONTEXT.md section 6).

Agreed minimum scope: repository list, audit history, finding detail with per-agent evidence
breakdown, and taint path rendering. Anything beyond that is undecided - see PROJECT_CONTEXT.md
section 7, open question 2.
