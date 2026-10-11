/**
 * TypeScript mirrors of CodeSheriff contract v2.0.0.
 *
 * These mirror `packages/contracts/src/codesheriff_contracts/contracts.py` — the frozen shapes
 * the agents and the engine already speak. They are NOT the dashboard's API contract: what the
 * REST endpoints return is Chapter 15's decision, and the original plan's mistake was defining
 * dashboard data contracts five chapters before the contract itself was frozen (PLAN.md).
 *
 * Nothing here fetches. The dashboard is a rendering layer only (§6): no business logic, no
 * database access, no detection logic in TypeScript.
 */

/** The closed set. Widening it invalidates every number fitted against it (§6). */
export const IN_SCOPE_CWES = [
  "CWE-22",
  "CWE-78",
  "CWE-79",
  "CWE-89",
  "CWE-94",
  "CWE-502",
  "CWE-639",
  "CWE-798",
  "CWE-862",
  "CWE-918",
] as const;

export type Cwe = (typeof IN_SCOPE_CWES)[number];

export const CWE_TITLES: Record<Cwe, string> = {
  "CWE-22": "Path traversal",
  "CWE-78": "OS command injection",
  "CWE-79": "Cross-site scripting",
  "CWE-89": "SQL injection",
  "CWE-94": "Code injection",
  "CWE-502": "Deserialisation of untrusted data",
  "CWE-639": "Authorisation bypass through user-controlled key",
  "CWE-798": "Hard-coded credentials",
  "CWE-862": "Missing authorisation",
  "CWE-918": "Server-side request forgery",
};

/**
 * What an agent is actually saying. Three states, never two.
 *
 * The distinction that matters is between the second and the third, and it has to survive into the
 * UI: an agent that ran and found nothing is evidence, and an agent that could not run is evidence
 * of nothing at all. A findings page that renders only detections cannot explain its own posterior
 * (PLAN.md Chapter 16).
 */
export type EvidenceKind = "detection" | "silence" | "abstention";

export type AgentId =
  | "structural.taint"
  | "structural.semgrep"
  | "semantic.hosted"
  | "context.rag"
  | "runtime.sfi";

export const AGENT_LABELS: Record<AgentId, string> = {
  "structural.taint": "Taint engine",
  "structural.semgrep": "Semgrep",
  "semantic.hosted": "Semantic (hosted LLM)",
  "context.rag": "Repository precedent",
  "runtime.sfi": "Runtime sandbox",
};

export interface Artifact {
  artifactType: string;
  content: unknown;
}

export interface Evidence {
  agentId: AgentId;
  agentVersion: string;
  unitId: string;
  kind: EvidenceKind;
  /** DETECTION only — a 16-character digest from `finding_key()`. */
  findingKey: string | null;
  /** DETECTION only, always in scope. */
  cwe: Cwe | null;
  /** SILENCE only: what this agent was actually capable of finding. */
  coveredCwes: Cwe[];
  /** ABSTENTION only: a machine-readable cause, e.g. `unit_too_large`. */
  reason: string | null;
  rawScore: number;
  confidence: number;
  explanation: string;
  artifacts: Artifact[];
}

/**
 * One fitted calibration artifact.
 *
 * `isProvisional` is the field the UI must never ignore. Until Chapter 14 fits ratios against the
 * calibration split, fusion runs on hand-set numbers, and D-010 forbids presenting anything
 * hand-set as calibrated. Every posterior on screen is rendered through `<Posterior>`, which reads
 * this.
 */
export interface Calibration {
  id: string;
  isProvisional: boolean;
  /** Expected calibration error. Null while provisional — there is nothing to measure yet. */
  ece: number | null;
  brier: number | null;
  nCases: number | null;
  corpusHash: string | null;
}

export interface Finding {
  findingKey: string;
  cwe: Cwe;
  posterior: number;
  isAlertWorthy: boolean;
  severity: "low" | "medium" | "high" | "critical";
  /** The threshold this finding was judged against, not today's setting. */
  alertThreshold: number;
  priorProbability: number;
  file: string;
  qualifiedSymbol: string;
  lineNumbers: number[];
  title: string;
  evidence: Evidence[];
}

export type AuditStatus = "queued" | "running" | "succeeded" | "failed";

export interface Audit {
  id: string;
  repositoryFullName: string;
  prNumber: number;
  prTitle: string;
  headSha: string;
  status: AuditStatus;
  createdAt: string;
  durationSeconds: number | null;
  unitsAnalysed: number;
  findings: Finding[];
  calibration: Calibration;
}

export interface Repository {
  id: number;
  fullName: string;
  defaultBranch: string;
  isPrivate: boolean;
  analysisEnabled: boolean;
  lastAuditAt: string | null;
  openAlerts: number;
}
