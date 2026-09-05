"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

import { EvidenceKindBadge } from "@/components/evidence-kind-badge";
import { Posterior } from "@/components/posterior";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { getAudit, toCalibration, type AuditDetail, type EvidenceOut } from "@/lib/api";
import { AGENT_LABELS, CWE_TITLES, type AgentId, type Cwe } from "@/lib/types";

/**
 * One audit: what it looked at, what each witness said about it, and what that fused into.
 *
 * A client component, like everything else that reads the API. The session cookie belongs to the
 * API's origin; a server component could forward it in development, where the two share a host,
 * and would break the day the API moves to its own subdomain.
 *
 * **Every unit is listed, including the quiet ones.** An audit that analysed forty functions and
 * found nothing in thirty-nine has said something about all forty, and a page that showed only
 * the one with a finding would make the posterior on that one unexplainable. Silences and
 * abstentions render with the same weight as detections for the same reason.
 */
export default function AuditPage() {
  const params = useParams<{ id: string }>();
  const [audit, setAudit] = useState<AuditDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getAudit(params.id)
      .then((data) => !cancelled && setAudit(data))
      .catch((caught: unknown) => {
        if (!cancelled) {
          setError(caught instanceof Error ? caught.message : "Could not load that audit.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [params.id]);

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertTitle>Could not load that audit</AlertTitle>
        <AlertDescription>
          {error} It may belong to an installation this account cannot see.
        </AlertDescription>
      </Alert>
    );
  }

  if (!audit) {
    return (
      <div className="flex flex-col gap-3">
        <Skeleton className="h-8 w-72" />
        <Skeleton className="h-32 w-full" />
      </div>
    );
  }

  const calibration = toCalibration(audit.calibration);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <Link href="/audits" className="text-muted-foreground text-sm hover:underline">
          ← Audits
        </Link>
        <h1 className="mt-1 text-2xl font-semibold tracking-tight">
          {audit.repository_full_name} #{audit.pr_number}
        </h1>
        <p className="text-muted-foreground font-mono text-xs">
          {audit.head_sha.slice(0, 12)} · {audit.status} · {audit.unit_count} unit
          {audit.unit_count === 1 ? "" : "s"}
          {audit.duration_seconds !== null && ` · ${audit.duration_seconds.toFixed(1)}s`}
          {" · "}
          contract {audit.contract_version}
        </p>
      </div>

      {audit.error_reason && (
        <Alert variant="destructive">
          <AlertTitle>This audit failed</AlertTitle>
          <AlertDescription>
            {audit.error_reason} A failed audit is not a clean bill of health — nothing was
            concluded about this pull request.
          </AlertDescription>
        </Alert>
      )}

      {audit.units_returned < audit.unit_count && (
        <Alert>
          <AlertTitle>Showing the first {audit.units_returned} units</AlertTitle>
          <AlertDescription>
            This audit analysed {audit.unit_count}. The counts above are the true ones.
          </AlertDescription>
        </Alert>
      )}

      <section className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold tracking-tight">Findings</h2>
        {audit.findings.length === 0 ? (
          <Card>
            <CardContent className="text-muted-foreground py-4 text-sm">
              No unit produced a finding. That is a result, not an absence of one: every witness
              that ran and covered a weakness reported silence on it, and a silence carries a
              likelihood ratio below 1.0.
            </CardContent>
          </Card>
        ) : (
          audit.findings.map((finding) => (
            <Card key={finding.finding_key}>
              <CardHeader className="flex flex-row items-start justify-between gap-4">
                <div className="min-w-0">
                  <CardTitle className="text-base">
                    {finding.title || `${finding.cwe} in ${finding.qualified_symbol}`}
                  </CardTitle>
                  <p className="text-muted-foreground mt-1 font-mono text-xs break-all">
                    {finding.file}
                    {finding.line_numbers.length > 0 && `:${finding.line_numbers.join(", ")}`} ·{" "}
                    {finding.qualified_symbol}
                  </p>
                  <div className="mt-2 flex flex-wrap items-center gap-2">
                    <Badge variant="secondary" className="font-mono">
                      {finding.cwe}
                    </Badge>
                    <span className="text-muted-foreground text-xs">
                      {CWE_TITLES[finding.cwe as Cwe] ?? ""}
                    </span>
                    {finding.is_alert_worthy && <Badge variant="destructive">alert</Badge>}
                  </div>
                  {finding.consensus_rationale && (
                    <p className="mt-2 text-sm">{finding.consensus_rationale}</p>
                  )}
                </div>
                <Posterior
                  value={finding.posterior_probability}
                  calibration={calibration}
                  threshold={finding.alert_threshold}
                />
              </CardHeader>
            </Card>
          ))
        )}
        <p className="text-muted-foreground text-xs">
          Judged against the threshold this audit ran under (
          {(audit.alert_threshold * 100).toFixed(1)}%), from a prior of{" "}
          {(audit.prior_probability * 100).toFixed(1)}%. A threshold selected later does not
          retroactively change which of these were alerts.
        </p>
      </section>

      <section className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold tracking-tight">What was analysed</h2>
        <p className="text-muted-foreground text-sm">
          One unit per changed function, and one statement per witness on each. An agent that could
          not look does not vote the code innocent — it abstains, at a likelihood ratio of exactly
          1.0.
        </p>
        {audit.units.length === 0 ? (
          <Card>
            <CardContent className="text-muted-foreground py-4 text-sm">
              This pull request contained no analysable Python function.
            </CardContent>
          </Card>
        ) : (
          audit.units.map((unit) => (
            <Card key={unit.unit_id}>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium break-all">
                  {unit.qualified_symbol}
                  <span className="text-muted-foreground ml-2 font-mono text-xs">
                    {unit.file}:{unit.start_line}
                  </span>
                </CardTitle>
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  {unit.is_test_file && <Badge variant="outline">test file</Badge>}
                  {unit.decorators.map((decorator) => (
                    <Badge key={decorator} variant="outline" className="font-mono text-[10px]">
                      @{decorator}
                    </Badge>
                  ))}
                  <span className="text-muted-foreground text-xs">
                    {unit.post_src_lines} lines · {unit.changed_lines.length} changed
                  </span>
                </div>
              </CardHeader>
              <Separator />
              <CardContent className="flex flex-col gap-3 pt-3">
                {unit.evidence.map((statement, index) => (
                  <Statement key={`${statement.agent_id}-${index}`} evidence={statement} />
                ))}
              </CardContent>
            </Card>
          ))
        )}
      </section>
    </div>
  );
}

/**
 * One agent statement, rendered so the three kinds stay distinguishable.
 *
 * A silence names the weaknesses it covered; an abstention names why it could not look. Rendering
 * both as "found nothing" is precisely the collapse that makes a posterior unexplainable.
 */
function Statement({ evidence }: { evidence: EvidenceOut }) {
  const label = AGENT_LABELS[evidence.agent_id as AgentId] ?? evidence.agent_id;
  return (
    <div className="flex flex-col gap-1">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm font-medium">
          {label}
          <span className="text-muted-foreground ml-2 font-mono text-xs">
            v{evidence.agent_version}
          </span>
        </span>
        <div className="flex items-center gap-2">
          {evidence.kind === "detection" && (
            <Badge variant="secondary" className="font-mono text-[10px]">
              {evidence.cwe} · score {evidence.raw_score.toFixed(2)}
            </Badge>
          )}
          <EvidenceKindBadge kind={evidence.kind} />
        </div>
      </div>
      <p className="text-muted-foreground text-sm">{evidence.explanation}</p>
      {evidence.kind === "silence" && evidence.covered_cwes.length > 0 && (
        <p className="text-muted-foreground text-xs">
          Covers{" "}
          {evidence.covered_cwes.map((cwe) => (
            <Badge key={cwe} variant="outline" className="mr-1 font-mono text-[10px]">
              {cwe}
            </Badge>
          ))}
        </p>
      )}
      {evidence.kind === "abstention" && evidence.reason && (
        <p className="text-muted-foreground font-mono text-xs">reason: {evidence.reason}</p>
      )}
    </div>
  );
}
