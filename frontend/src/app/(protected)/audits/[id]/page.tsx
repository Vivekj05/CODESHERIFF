"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  Copy,
  ExternalLink,
  FileCode,
  FileDiff,
  Network,
  Shield,
  ShieldAlert,
  Sparkles,
} from "lucide-react";

import { EvidenceKindBadge } from "@/components/evidence-kind-badge";
import { Posterior } from "@/components/posterior";
import { MermaidViewer } from "@/components/reviews/mermaid-viewer";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { getAudit, toCalibration, type AuditDetail, type EvidenceOut } from "@/lib/api";
import { getRichReviewForAudit, type RichReviewData } from "@/lib/gemini-review";
import { AGENT_LABELS, CWE_TITLES, type AgentId, type Cwe } from "@/lib/types";

type ReviewTab = "architecture" | "walkthrough" | "findings" | "suggestions";

export default function AuditPage() {
  const params = useParams<{ id: string }>();
  const [audit, setAudit] = useState<AuditDetail | null>(null);
  const [richReview, setRichReview] = useState<RichReviewData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<ReviewTab>("architecture");
  const [copiedDiffIndex, setCopiedDiffIndex] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    getAudit(params.id)
      .then((data) => {
        if (!cancelled) {
          setAudit(data);
          getRichReviewForAudit(data).then((rev) => {
            if (!cancelled) setRichReview(rev);
          });
        }
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

  function copyDiff(text: string, index: number) {
    navigator.clipboard.writeText(text);
    setCopiedDiffIndex(index);
    setTimeout(() => setCopiedDiffIndex(null), 2000);
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Back and Header */}
      <div className="flex flex-col gap-2">
        <Link
          href="/audits"
          className="text-muted-foreground text-xs hover:text-foreground inline-flex items-center gap-1.5 transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Back to Audits</span>
        </Link>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-1">
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-2xl font-semibold tracking-tight">
                {audit.repository_full_name} #{audit.pr_number}
              </h1>
              {alertCount > 0 ? (
                <Badge variant="destructive" className="font-mono text-xs gap-1">
                  <ShieldAlert className="h-3 w-3" />
                  {alertCount} Alert{alertCount === 1 ? "" : "s"}
                </Badge>
              ) : (
                <Badge variant="outline" className="font-mono text-xs gap-1 text-emerald-400 border-emerald-500/30 bg-emerald-500/10">
                  <CheckCircle2 className="h-3 w-3" />
                  Clean Audit
                </Badge>
              )}
            </div>

            <p className="text-muted-foreground font-mono text-xs mt-1">
              Commit <code className="bg-muted px-1 py-0.5 rounded">{audit.head_sha.slice(0, 7)}</code> · {audit.status} ·{" "}
              {audit.unit_count} function unit{audit.unit_count === 1 ? "" : "s"}
              {audit.duration_seconds !== null && ` · ${audit.duration_seconds.toFixed(1)}s`}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" nativeButton={false} render={<a href={githubPrUrl} target="_blank" rel="noreferrer" className="text-xs gap-1.5 flex items-center"><span>View on GitHub</span><ExternalLink className="h-3.5 w-3.5" /></a>} />
          </div>
        </div>
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

      {/* Review Navigation Tabs */}
      <div className="flex border-b border-border/80 gap-1 overflow-x-auto">
        <button
          onClick={() => setActiveTab("architecture")}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap ${
            activeTab === "architecture"
              ? "border-primary text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground"
          }`}
        >
          <Network className="h-3.5 w-3.5" />
          <span>Architecture & Flow</span>
        </button>

        <button
          onClick={() => setActiveTab("walkthrough")}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap ${
            activeTab === "walkthrough"
              ? "border-primary text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground"
          }`}
        >
          <FileCode className="h-3.5 w-3.5" />
          <span>Walkthrough & Summary</span>
        </button>

        <button
          onClick={() => setActiveTab("findings")}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap ${
            activeTab === "findings"
              ? "border-primary text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground"
          }`}
        >
          <Shield className="h-3.5 w-3.5" />
          <span>Calibrated Findings ({audit.findings.length})</span>
        </button>

        <button
          onClick={() => setActiveTab("suggestions")}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap ${
            activeTab === "suggestions"
              ? "border-primary text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground"
          }`}
        >
          <FileDiff className="h-3.5 w-3.5" />
          <span>Suggestions & Repairs</span>
        </button>
      </div>

      {/* TAB 1: Architecture & Sequence Diagram */}
      {activeTab === "architecture" && (
        <div className="flex flex-col gap-6">
          <div>
            <h2 className="text-base font-semibold tracking-tight">Sequence Diagram & Control Flow</h2>
            <p className="text-muted-foreground text-xs">
              Component interactions, caller boundaries, and data flow mapped from this PR&apos;s modified functions.
            </p>
          </div>

          {richReview ? (
            <MermaidViewer chart={richReview.sequenceDiagram} />
          ) : (
            <Skeleton className="h-72 w-full rounded-xl" />
          )}

          {richReview && richReview.strengths.length > 0 && (
            <Card className="border-border/70 bg-card/60">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Sparkles className="h-4 w-4 text-emerald-400" />
                  <span>Observed Engineering Strengths</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="text-xs text-muted-foreground flex flex-col gap-2">
                {richReview.strengths.map((str, idx) => (
                  <div key={idx} className="flex items-start gap-2">
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0 mt-0.5" />
                    <span>{str}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* TAB 2: Walkthrough & Summary */}
      {activeTab === "walkthrough" && (
        <div className="flex flex-col gap-6">
          <Card className="border-border/70 bg-card/60">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold">Executive Architecture Summary</CardTitle>
            </CardHeader>
            <CardContent className="text-xs sm:text-sm text-muted-foreground leading-relaxed">
              {richReview ? richReview.summary : "Analyzing pull request change footprint..."}
            </CardContent>
          </Card>

          <div className="flex flex-col gap-3">
            <h2 className="text-base font-semibold tracking-tight">File-by-File Change Walkthrough</h2>
            {richReview &&
              richReview.walkthrough.map((item, idx) => (
                <Card key={idx} className="border-border/60 bg-muted/20">
                  <CardHeader className="py-3 px-4 flex flex-row items-center justify-between">
                    <div className="flex items-center gap-2">
                      <FileCode className="h-4 w-4 text-primary shrink-0" />
                      <span className="font-mono text-xs font-medium text-foreground">{item.file}</span>
                    </div>
                    <Badge variant="outline" className="text-[10px] font-mono capitalize">
                      {item.action}
                    </Badge>
                  </CardHeader>
                  <Separator />
                  <CardContent className="py-3 px-4 text-xs text-muted-foreground flex flex-col gap-2">
                    <p>{item.summary}</p>
                    {item.functions.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1.5 pt-1">
                        <span className="text-[11px] text-foreground">Symbols:</span>
                        {item.functions.map((fn, fIdx) => (
                          <code key={fIdx} className="bg-background px-1.5 py-0.5 rounded text-[11px] font-mono border border-border/60">
                            {fn}
                          </code>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
          </div>
        </div>
      )}

      {/* TAB 3: Calibrated Security Findings */}
      {activeTab === "findings" && (
        <div className="flex flex-col gap-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold tracking-tight">Calibrated Security Findings</h2>
              <p className="text-muted-foreground text-xs">
                Each posterior probability is fused from four blind specialist agents using empirical likelihood ratios.
              </p>
            </div>
            <Badge variant="secondary" className="font-mono text-xs">
              Threshold: {(audit.alert_threshold * 100).toFixed(1)}%
            </Badge>
          </div>

          {audit.findings.length === 0 ? (
            <Card className="border-border/60 bg-card/40">
              <CardContent className="text-muted-foreground py-8 text-center text-sm flex flex-col items-center gap-2">
                <CheckCircle2 className="h-8 w-8 text-emerald-400" />
                <span className="font-medium text-foreground">No Security Findings Detected</span>
                <span className="text-xs max-w-md">
                  Every specialist agent that covered weaknesses reported silence on these functions. A silence carries an empirical likelihood ratio below 1.0.
                </span>
              </CardContent>
            </Card>
          ) : (
            audit.findings.map((finding) => (
              <Card key={finding.finding_key} className="border-border/70 bg-card/60">
                <CardHeader className="flex flex-row items-start justify-between gap-4 pb-3">
                  <div className="min-w-0">
                    <CardTitle className="text-base">
                      <Link
                        href={`/audits/${audit.id}/findings/${finding.finding_key}`}
                        className="hover:underline flex items-center gap-2"
                      >
                        <span>{finding.title || `${finding.cwe} in ${finding.qualified_symbol}`}</span>
                      </Link>
                    </CardTitle>
                    <p className="text-muted-foreground mt-1 font-mono text-xs break-all">
                      {finding.file}
                      {finding.line_numbers.length > 0 && `:${finding.line_numbers.join(", ")}`} ·{" "}
                      {finding.qualified_symbol}
                    </p>
                    <div className="mt-2 flex flex-wrap items-center gap-2">
                      <Badge variant="secondary" className="font-mono text-xs">
                        {finding.cwe}
                      </Badge>
                      <span className="text-muted-foreground text-xs">
                        {CWE_TITLES[finding.cwe as Cwe] ?? ""}
                      </span>
                      {finding.is_alert_worthy && (
                        <Badge variant="destructive" className="text-[10px] uppercase font-mono">
                          alert
                        </Badge>
                      )}
                    </div>
                    {finding.consensus_rationale && (
                      <p className="mt-2 text-xs sm:text-sm text-foreground/90">{finding.consensus_rationale}</p>
                    )}
                  </div>
                  <Link
                    href={`/audits/${audit.id}/findings/${finding.finding_key}`}
                    aria-label="How this posterior was reached"
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

          {/* Unit breakdown */}
          <div className="flex flex-col gap-3 pt-4">
            <h3 className="text-sm font-semibold tracking-tight">Analysed Functions ({audit.units.length})</h3>
            {audit.units.map((unit) => (
              <Card key={unit.unit_id} className="border-border/60 bg-muted/20">
                <CardHeader className="py-2.5 px-4">
                  <CardTitle className="text-xs font-mono font-medium flex items-center justify-between">
                    <span>
                      {unit.qualified_symbol} ({unit.file}:{unit.start_line})
                    </span>
                    <span className="text-muted-foreground font-normal">
                      {unit.changed_lines.length} changed lines
                    </span>
                  </CardTitle>
                </CardHeader>
                <Separator />
                <CardContent className="p-3 flex flex-col gap-2.5">
                  {unit.evidence.map((statement, idx) => (
                    <Statement key={`${statement.agent_id}-${idx}`} evidence={statement} />
                  ))}
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* TAB 4: Suggestions & Repairs */}
      {activeTab === "suggestions" && (
        <div className="flex flex-col gap-6">
          <div>
            <h2 className="text-base font-semibold tracking-tight">Verified Code Suggestions & Diffs</h2>
            <p className="text-muted-foreground text-xs">
              Suggested code repairs passing the deterministic AST verification ladder. CodeSheriff never commits automatically.
            </p>
          </div>

          {richReview &&
            richReview.suggestions.map((sug, idx) => (
              <Card key={idx} className="border-border/70 bg-card/60">
                <CardHeader className="pb-3 flex flex-row items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <CardTitle className="text-sm font-semibold">{sug.title}</CardTitle>
                      {sug.severity === "critical" && (
                        <Badge variant="destructive" className="text-[10px] font-mono uppercase">
                          Critical Fix
                        </Badge>
                      )}
                    </div>
                    <CardDescription className="text-xs font-mono mt-1">
                      {sug.file}:{sug.line}
                    </CardDescription>
                  </div>

                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => copyDiff(sug.diff, idx)}
                    className="h-7 text-xs gap-1.5"
                  >
                    <Copy className="h-3 w-3" />
                    <span>{copiedDiffIndex === idx ? "Copied" : "Copy Diff"}</span>
                  </Button>
                </CardHeader>
                <Separator />
                <CardContent className="pt-3 flex flex-col gap-3">
                  <p className="text-xs text-muted-foreground">{sug.rationale}</p>
                  <pre className="rounded-lg bg-background/90 p-3 font-mono text-xs text-foreground overflow-x-auto border border-border/80">
                    {sug.diff}
                  </pre>
                </CardContent>
              </Card>
            ))}
        </div>
      )}
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
            <Badge variant="secondary" className="font-mono text-[10px] py-0">
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
