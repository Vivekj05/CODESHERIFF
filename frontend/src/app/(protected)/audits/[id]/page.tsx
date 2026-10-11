"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowLeft, ExternalLink } from "lucide-react";

import { buttonVariants } from "@/components/chai/button";
import { Chip } from "@/components/chai/chip";
import { EvidenceKindBadge } from "@/components/evidence-kind-badge";
import { PageHeader } from "@/components/page-header";
import { Posterior } from "@/components/posterior";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { getAudit, toCalibration, type AuditDetail, type EvidenceOut } from "@/lib/api";
import { AGENT_LABELS, CWE_TITLES, type AgentId, type Cwe } from "@/lib/types";

/**
 * One audit: what every witness said about every changed function, and the findings fusion made
 * of it. Everything here is read from the audit's own rows; nothing is generated in the browser.
 */
export default function AuditPage() {
  const params = useParams<{ id: string }>();
  const [audit, setAudit] = useState<AuditDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getAudit(params.id)
      .then((data) => {
        if (!cancelled) setAudit(data);
      })
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
      <div className="flex flex-col gap-4">
        <Skeleton className="h-8 w-72" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  const calibration = toCalibration(audit.calibration);
  const githubPrUrl = `https://github.com/${audit.repository_full_name}/pull/${audit.pr_number}`;
  const alertCount = audit.findings.filter((f) => f.is_alert_worthy).length;

  return (
    <div className="flex flex-col gap-10">
      <div className="flex flex-col gap-4">
        <Link
          href="/audits"
          className="inline-flex w-fit items-center gap-1.5 text-sm text-muted-foreground transition-colors duration-200 hover:text-foreground"
        >
          <ArrowLeft className="size-3.5" aria-hidden="true" />
          All audits
        </Link>
        <PageHeader
          title={`${audit.repository_full_name} #${audit.pr_number}`}
          action={
            <a href={githubPrUrl} target="_blank" rel="noreferrer" className={buttonVariants({ variant: "outline" })}>
              View on GitHub
              <ExternalLink className="-ml-1" aria-hidden="true" />
            </a>
          }
        />
        <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
          {alertCount > 0 ? (
            <Chip tone="danger">
              {alertCount} alert{alertCount === 1 ? "" : "s"}
            </Chip>
          ) : (
            <Chip tone="success">no alerts</Chip>
          )}
          <span className="font-mono text-xs">{audit.head_sha.slice(0, 7)}</span>
          <span aria-hidden="true">·</span>
          <span>{audit.status}</span>
          <span aria-hidden="true">·</span>
          <span>
            {audit.unit_count} function{audit.unit_count === 1 ? "" : "s"}
          </span>
          {audit.duration_seconds !== null && (
            <>
              <span aria-hidden="true">·</span>
              <span>{audit.duration_seconds.toFixed(1)}s</span>
            </>
          )}
        </div>
      </div>

      {audit.error_reason && (
        <Alert variant="destructive">
          <AlertTitle>This audit failed</AlertTitle>
          <AlertDescription>
            {audit.error_reason} A failed audit is not a clean result: nothing was concluded about
            this pull request.
          </AlertDescription>
        </Alert>
      )}

      <section aria-labelledby="findings-h" className="flex flex-col gap-4">
        <div className="flex flex-wrap items-end justify-between gap-2">
          <div>
            <h2 id="findings-h" className="text-xl font-medium">
              Findings
            </h2>
            <p className="text-sm text-muted-foreground">
              Each probability multiplies one fitted ratio per witness onto the prior.
            </p>
          </div>
          <span className="text-sm text-muted-foreground">
            Alert threshold{" "}
            <span className="font-mono text-foreground">{(audit.alert_threshold * 100).toFixed(1)}%</span>
          </span>
        </div>

        {audit.findings.length === 0 ? (
          <Card>
            <CardContent className="py-8 text-center text-sm text-muted-foreground">
              No witness detected anything in these functions. The statements below say what each
              one checked, and what it could not.
            </CardContent>
          </Card>
        ) : (
          audit.findings.map((finding) => (
            <Card key={finding.finding_key}>
              <CardHeader className="flex flex-row items-start justify-between gap-4">
                <div className="min-w-0">
                  <CardTitle>
                    <Link
                      href={`/audits/${audit.id}/findings/${finding.finding_key}`}
                      className="underline-offset-4 hover:underline"
                    >
                      {finding.title || `${finding.cwe} in ${finding.qualified_symbol}`}
                    </Link>
                  </CardTitle>
                  <p className="mt-1 font-mono text-xs break-all text-muted-foreground">
                    {finding.file}
                    {finding.line_numbers.length > 0 && `:${finding.line_numbers.join(", ")}`} ·{" "}
                    {finding.qualified_symbol}
                  </p>
                  <div className="mt-2 flex flex-wrap items-center gap-2">
                    <Badge variant="outline" className="font-mono">
                      {finding.cwe}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      {CWE_TITLES[finding.cwe as Cwe] ?? ""}
                    </span>
                    {finding.is_alert_worthy && <Chip tone="danger">alert</Chip>}
                  </div>
                  {finding.consensus_rationale && (
                    <p className="mt-2 text-sm text-foreground/90">{finding.consensus_rationale}</p>
                  )}
                </div>
                <Link
                  href={`/audits/${audit.id}/findings/${finding.finding_key}`}
                  aria-label="How this probability was reached"
                  className="shrink-0"
                >
                  <Posterior
                    value={finding.posterior_probability}
                    calibration={calibration}
                    threshold={finding.alert_threshold}
                  />
                </Link>
              </CardHeader>
            </Card>
          ))
        )}
      </section>

      <section aria-labelledby="units-h" className="flex flex-col gap-4">
        <div>
          <h2 id="units-h" className="text-xl font-medium">
            What each witness said
          </h2>
          <p className="text-sm text-muted-foreground">
            One statement per witness per function, including the ones that found nothing.
          </p>
        </div>
        {audit.units.map((unit) => (
          <Card key={unit.unit_id}>
            <CardHeader>
              <CardTitle className="flex flex-wrap items-center justify-between gap-2 font-mono text-sm font-medium">
                <span className="break-all">
                  {unit.qualified_symbol} ({unit.file}:{unit.start_line})
                </span>
                <span className="font-sans text-xs font-normal text-muted-foreground">
                  {unit.changed_lines.length} changed line{unit.changed_lines.length === 1 ? "" : "s"}
                </span>
              </CardTitle>
            </CardHeader>
            <Separator />
            <CardContent className="flex flex-col gap-3">
              {unit.evidence.map((statement, idx) => (
                <Statement key={`${statement.agent_id}-${idx}`} evidence={statement} />
              ))}
            </CardContent>
          </Card>
        ))}
      </section>
    </div>
  );
}

function Statement({ evidence }: { evidence: EvidenceOut }) {
  const label = AGENT_LABELS[evidence.agent_id as AgentId] ?? evidence.agent_id;
  return (
    <div className="flex flex-col gap-1 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-medium text-foreground">
          {label}
          <span className="text-muted-foreground ml-2 font-mono text-[10px]">
            v{evidence.agent_version}
          </span>
        </span>
        <div className="flex items-center gap-1.5">
          {evidence.kind === "detection" && (
            <Badge variant="outline" className="font-mono text-[10px]">
              {evidence.cwe} · {evidence.raw_score.toFixed(2)}
            </Badge>
          )}
          <EvidenceKindBadge kind={evidence.kind} />
        </div>
      </div>
      <p className="text-muted-foreground">{evidence.explanation}</p>
    </div>
  );
}
