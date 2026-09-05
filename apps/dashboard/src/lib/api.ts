/**
 * The only place the dashboard talks to the backend.
 *
 * §6 makes this a rendering layer: no client secret lives here, no code is exchanged here, and
 * nothing here calls GitHub. Sign-in is a browser navigation to the FastAPI edge, which owns the
 * OAuth secret and sets an HttpOnly session cookie the JavaScript on this page cannot read.
 *
 * `credentials: "include"` on every call is what sends that cookie. The API allows exactly one
 * origin, so a page on another site cannot make these calls with the user's session.
 */

import type { Calibration } from "@/lib/types";

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export interface SessionInfo {
  login: string;
  name: string | null;
  avatar_url: string | null;
  installation_count: number;
  expires_at: string;
  install_url: string | null;
}

export interface RepositoryOut {
  id: number;
  full_name: string;
  default_branch: string;
  is_private: boolean;
  analysis_enabled: boolean;
}

export interface RepositoryPage {
  items: RepositoryOut[];
  next_cursor: string | null;
}

/** Thrown for any non-2xx response. `status` is what callers branch on — 401 means "sign in". */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(init.headers ?? {}) },
  });

  if (!response.ok) {
    // The API answers 501 when no GitHub App is configured. Surfacing that distinctly is the
    // difference between "you are signed out" and "this deployment was never finished".
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      // A non-JSON error body is still an error; the status carries the meaning.
    }
    throw new ApiError(response.status, detail);
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export function signInUrl(nextPath = "/repositories"): string {
  return `${API_BASE_URL}/auth/login?next=${encodeURIComponent(nextPath)}`;
}

export function getSession(): Promise<SessionInfo> {
  return request<SessionInfo>("/auth/session");
}

export function logout(): Promise<void> {
  return request<void>("/auth/logout", { method: "POST" });
}

export function listRepositories(cursor?: string | null, limit = 30): Promise<RepositoryPage> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (cursor) params.set("cursor", cursor);
  return request<RepositoryPage>(`/repositories?${params.toString()}`);
}

export function setAnalysisEnabled(
  repoId: number,
  enabled: boolean,
): Promise<RepositoryOut> {
  return request<RepositoryOut>(`/repositories/${repoId}`, {
    method: "PATCH",
    body: JSON.stringify({ analysis_enabled: enabled }),
  });
}

/* ---------------------------------------------------------------------------
 * Chapter 15: the read side.
 *
 * These mirror the FastAPI response models field for field, in snake_case, because renaming on
 * the way in gives two names for one field and a mapping layer nobody maintains. `src/lib/types.ts`
 * mirrors the *contract*; these mirror the *API*, and PLAN.md is explicit that they are not the
 * same thing.
 * ------------------------------------------------------------------------- */

export interface AuditSummary {
  id: string;
  repository_id: number;
  repository_full_name: string;
  pr_number: number;
  head_sha: string;
  status: string;
  created_at: string;
  duration_seconds: number | null;
  error_reason: string | null;
  prior_probability: number;
  alert_threshold: number;
  units: number;
  findings: number;
  alerts: number;
  top_posterior: number | null;
}

export interface AuditPage {
  items: AuditSummary[];
  next_cursor: string | null;
}

/** One agent's statement. Three kinds, never two — see `EvidenceKind` in `types.ts`. */
export interface EvidenceOut {
  agent_id: string;
  agent_version: string;
  kind: "detection" | "silence" | "abstention";
  finding_key: string | null;
  cwe: string | null;
  covered_cwes: string[];
  reason: string | null;
  raw_score: number;
  confidence: number;
  explanation: string;
}

export interface ChangeUnitOut {
  unit_id: string;
  file: string;
  qualified_symbol: string;
  language: string;
  start_line: number;
  changed_lines: number[];
  decorators: string[];
  is_test_file: boolean;
  post_src_lines: number;
  evidence: EvidenceOut[];
}

export interface FindingOut {
  finding_key: string;
  cwe: string;
  posterior_probability: number;
  is_alert_worthy: boolean;
  severity: string;
  prior_probability: number;
  alert_threshold: number;
  file: string | null;
  qualified_symbol: string | null;
  line_numbers: number[];
  title: string;
  consensus_rationale: string;
}

/** The calibration artifact **this audit ran under**, not today's. */
export interface AuditCalibration {
  id: string;
  is_provisional: boolean;
  corpus_hash: string | null;
  split_hash: string | null;
  ece: number | null;
  brier: number | null;
  n_cases: number | null;
}

export interface AuditDetail {
  id: string;
  repository_id: number;
  repository_full_name: string;
  pr_number: number;
  head_sha: string;
  base_sha: string;
  status: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  error_reason: string | null;
  github_comment_id: number | null;
  contract_version: string;
  prior_probability: number;
  alert_threshold: number;
  calibration: AuditCalibration | null;
  unit_count: number;
  units_returned: number;
  units: ChangeUnitOut[];
  findings: FindingOut[];
}

export interface WitnessActivity {
  agent_id: string;
  detections: number;
  silences: number;
  abstentions: number;
  statements: number;
}

export interface Overview {
  repositories: number;
  repositories_analysing: number;
  audits: number;
  audits_by_status: Record<string, number>;
  units_analysed: number;
  findings: number;
  alerts: number;
  by_cwe: { cwe: string; findings: number; alerts: number }[];
  witnesses: WitnessActivity[];
  latest_audit_at: string | null;
}

export interface ReliabilityBin {
  lower: number;
  upper: number;
  n: number;
  weight: number;
  mean_confidence: number;
  observed_frequency: number;
}

export interface CalibrationMetrics {
  split: string;
  n_claims: number;
  weighted: boolean;
  ece: number;
  brier: number;
  mean_posterior: number;
  observed_rate: number;
  bins: ReliabilityBin[];
  note: string;
}

export interface CellFit {
  n_vulnerable: number;
  n_safe: number;
  p_given_vulnerable: number;
  p_given_safe: number;
  raw_ratio: number;
  smoothed_ratio: number;
  ratio: number;
  clamped: string;
}

export interface WitnessFit {
  witness: string;
  n_vulnerable_claims: number;
  n_safe_claims: number;
  n_abstained: number;
  cells: Record<string, CellFit>;
}

export interface SweepPoint {
  threshold: number;
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1: number;
  n_alerts: number;
}

export interface CalibrationArtifact {
  schema_version: number;
  contract_version: string;
  generated: string;
  corpus_hash: string;
  split_hash: string;
  fit: {
    method: string;
    alpha: number;
    lr_min: number;
    lr_max: number;
    silence_ceiling: number;
    witnesses: Record<string, WitnessFit>;
  };
  prior: {
    base_rate: number;
    source: string;
    corpus_prevalence: number;
    rationale: string;
  };
  threshold: {
    value: number;
    objective: string;
    selected_on: string;
    weighted: boolean;
    base_rate: number;
    sweep: SweepPoint[];
    note: string;
  };
  metrics: Record<string, CalibrationMetrics>;
  provenance: Record<
    string,
    {
      platform: string;
      python_version: string;
      generated: string;
      agent_versions: Record<string, string>;
      backends_silent: string[];
      semantic_source: string;
    }
  >;
  notes: string;
}

export interface CalibrationResponse {
  source: string;
  artifact: CalibrationArtifact;
  witnesses: { witness: string; agents: string[] }[];
}

export function listAudits(cursor?: string | null, limit = 25): Promise<AuditPage> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (cursor) params.set("cursor", cursor);
  return request<AuditPage>(`/audits?${params.toString()}`);
}

export function getAudit(auditId: string): Promise<AuditDetail> {
  return request<AuditDetail>(`/audits/${encodeURIComponent(auditId)}`);
}

export function getOverview(): Promise<Overview> {
  return request<Overview>("/stats/overview");
}

export function getCalibration(): Promise<CalibrationResponse> {
  return request<CalibrationResponse>("/calibration");
}

/**
 * The API's calibration row in the shape `<Posterior>` reads.
 *
 * One adapter rather than a rename at the fetch boundary: `types.ts` mirrors the frozen contract
 * and this file mirrors the API, and the two are deliberately allowed to differ (PLAN.md). A null
 * row means the audit cites no calibration artifact at all, which is treated as provisional —
 * the safe direction, since the alternative is presenting an unwarranted number as measured.
 */
export function toCalibration(row: AuditCalibration | null): Calibration {
  if (!row) {
    return { id: "", isProvisional: true, ece: null, brier: null, nCases: null, corpusHash: null };
  }
  return {
    id: row.id,
    isProvisional: row.is_provisional,
    ece: row.ece,
    brier: row.brier,
    nCases: row.n_cases,
    corpusHash: row.corpus_hash,
  };
}
