/**
 * The fake data the shell renders. Replaced by real API calls in Chapter 15.
 *
 * Two properties of this dataset are deliberate rather than decorative.
 *
 * **The calibration is provisional.** No calibration artifact exists yet — Chapter 14 fits one
 * against the calibration split. Mock data claiming `isProvisional: false` would let the UI grow up
 * never having rendered the state it will actually be in for the next ten chapters.
 *
 * **Evidence includes silences and abstentions, not only detections.** A mock dataset of pure
 * detections quietly teaches every component the wrong shape, and Chapter 16 requires showing why
 * a posterior is what it is — which includes the agents that found nothing and the agents that
 * could not look.
 */

import type { Audit, Calibration, Repository } from "@/lib/types";

const PROVISIONAL: Calibration = {
  id: "00000000-0000-0000-0000-000000000000",
  isProvisional: true,
  ece: null,
  brier: null,
  nCases: null,
  corpusHash: null,
};

export const mockRepositories: Repository[] = [
  {
    id: 5001,
    fullName: "acme/payments-api",
    defaultBranch: "main",
    isPrivate: true,
    analysisEnabled: true,
    lastAuditAt: "2026-08-26T14:22:00Z",
    openAlerts: 2,
  },
  {
    id: 5002,
    fullName: "acme/internal-tools",
    defaultBranch: "main",
    isPrivate: true,
    analysisEnabled: true,
    lastAuditAt: "2026-08-24T09:05:00Z",
    openAlerts: 0,
  },
  {
    id: 5003,
    fullName: "acme/docs-site",
    defaultBranch: "trunk",
    isPrivate: false,
    analysisEnabled: false,
    lastAuditAt: null,
    openAlerts: 0,
  },
];

export const mockAudits: Audit[] = [
  {
    id: "a1f2c3d4",
    repositoryFullName: "acme/payments-api",
    prNumber: 418,
    prTitle: "Add refund lookup endpoint",
    headSha: "9f2c1ab",
    status: "succeeded",
    createdAt: "2026-08-26T14:22:00Z",
    durationSeconds: 142,
    unitsAnalysed: 6,
    calibration: PROVISIONAL,
    findings: [
      {
        findingKey: "3b7d1e5a90c4f218",
        cwe: "CWE-89",
        posterior: 0.87,
        isAlertWorthy: true,
        severity: "critical",
        alertThreshold: 0.7,
        priorProbability: 0.05,
        file: "app/refunds/queries.py",
        qualifiedSymbol: "RefundRepository.find_by_reference",
        lineNumbers: [61, 64],
        title: "Reference string reaches cursor.execute unsanitised",
        evidence: [
          {
            agentId: "structural.taint",
            agentVersion: "0.1.0",
            unitId: "u-418-1",
            kind: "detection",
            findingKey: "3b7d1e5a90c4f218",
            cwe: "CWE-89",
            coveredCwes: [],
            reason: null,
            rawScore: 0.91,
            confidence: 1.0,
            explanation:
              "request.args['reference'] flows into an f-string and then into cursor.execute with no sanitizer on the path.",
            artifacts: [],
          },
          {
            agentId: "semantic.hosted",
            agentVersion: "0.1.0",
            unitId: "u-418-1",
            kind: "detection",
            findingKey: "3b7d1e5a90c4f218",
            cwe: "CWE-89",
            coveredCwes: [],
            reason: null,
            rawScore: 0.78,
            confidence: 0.82,
            explanation:
              "The function accepts a caller-supplied reference and interpolates it into SQL. The trust boundary is the HTTP request; the invariant broken is that query structure must not depend on request data.",
            artifacts: [],
          },
          {
            agentId: "context.rag",
            agentVersion: "0.1.0",
            unitId: "u-418-1",
            kind: "silence",
            findingKey: null,
            cwe: null,
            coveredCwes: ["CWE-89", "CWE-22", "CWE-862"],
            reason: null,
            rawScore: 0.0,
            confidence: 1.0,
            explanation:
              "Searched this repository's merged pull requests and found no precedent for parameterising this query path.",
            artifacts: [],
          },
          {
            agentId: "runtime.sfi",
            agentVersion: "0.0.0",
            unitId: "u-418-1",
            kind: "abstention",
            findingKey: null,
            cwe: null,
            coveredCwes: [],
            reason: "agent_not_found",
            rawScore: 0.0,
            confidence: 0.0,
            explanation: "The runtime agent does not exist yet (PLAN.md Chapter 13).",
            artifacts: [],
          },
        ],
      },
      {
        findingKey: "c04a9821bd6e7f30",
        cwe: "CWE-862",
        posterior: 0.61,
        isAlertWorthy: false,
        severity: "medium",
        alertThreshold: 0.7,
        priorProbability: 0.05,
        file: "app/refunds/views.py",
        qualifiedSymbol: "RefundView.get",
        lineNumbers: [28],
        title: "@require_role decorator removed from an exported view",
        evidence: [
          {
            agentId: "semantic.hosted",
            agentVersion: "0.1.0",
            unitId: "u-418-2",
            kind: "detection",
            findingKey: "c04a9821bd6e7f30",
            cwe: "CWE-862",
            coveredCwes: [],
            reason: null,
            rawScore: 0.66,
            confidence: 0.71,
            explanation:
              "@require_role('finance') was present before the change and is absent after it, on a view that returns another customer's refund records.",
            artifacts: [],
          },
          {
            agentId: "structural.taint",
            agentVersion: "0.1.0",
            unitId: "u-418-2",
            kind: "silence",
            findingKey: null,
            cwe: null,
            coveredCwes: ["CWE-89", "CWE-78", "CWE-22", "CWE-94"],
            reason: null,
            rawScore: 0.0,
            confidence: 1.0,
            explanation:
              "No tainted path from a source to a sink in this unit. Holds no rules for CWE-862, so its silence says nothing about missing authorisation.",
            artifacts: [],
          },
        ],
      },
    ],
  },
  {
    id: "b7e8d9c0",
    repositoryFullName: "acme/payments-api",
    prNumber: 417,
    prTitle: "Bump httpx and tidy imports",
    headSha: "4d81ee0",
    status: "succeeded",
    createdAt: "2026-08-25T11:40:00Z",
    durationSeconds: 38,
    unitsAnalysed: 2,
    calibration: PROVISIONAL,
    findings: [],
  },
  {
    id: "e2a4b6c8",
    repositoryFullName: "acme/internal-tools",
    prNumber: 92,
    prTitle: "Export audit log to CSV",
    headSha: "77b3fa1",
    status: "failed",
    createdAt: "2026-08-24T09:05:00Z",
    durationSeconds: 12,
    unitsAnalysed: 0,
    calibration: PROVISIONAL,
    findings: [],
  },
];

export function findAudit(id: string): Audit | undefined {
  return mockAudits.find((audit) => audit.id === id);
}

export function findFinding(findingKey: string) {
  for (const audit of mockAudits) {
    const finding = audit.findings.find((f) => f.findingKey === findingKey);
    if (finding) return { audit, finding };
  }
  return undefined;
}
