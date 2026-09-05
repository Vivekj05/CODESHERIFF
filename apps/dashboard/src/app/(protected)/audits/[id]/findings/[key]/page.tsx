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
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  getFinding,
  toCalibration,
  type EvidenceDetail,
  type FindingDetail,
  type WitnessBreakdown,
} from "@/lib/api";
import { AGENT_LABELS, CWE_TITLES, type AgentId, type Cwe } from "@/lib/types";

/**
 * One finding, and the posterior taken apart factor by factor.
 *
 * This is the page the project's claim rests on. Every other security tool shows a developer a
 * number and asks to be believed; this one shows the four factors that produced it, the ratio-table
 * cell each factor was read from, and the statement each witness made — including the two kinds of
 * statement that say nothing was found.
 *
 * **Four witnesses are always drawn.** The roster comes from the API, which takes it from fusion,
 * not from the evidence. A list assembled from the agents that spoke would shorten to the ones that
 * alerted, and since every detection tier exceeds 1.0 that is a page on which the odds can only go
 * up — the D-007 defect, rendered.
 *
 * **Nothing here computes a probability.** The prior, the posterior, the threshold and every
 * likelihood ratio are read from the row that recorded them. The one arithmetic this page performs
 * is the product of the four ratios it is already showing, which is a claim about numbers on the
 * screen rather than a second opinion about the code.
 */
export default function FindingPage() {
  const params = useParams<{ id: string; key: string }>();
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getFinding(params.id, params.key)
      .then((data) => !cancelled && setDetail(data))
      .catch((caught: unknown) => {
        if (!cancelled) {
          setError(caught instanceof Error ? caught.message : "Could not load that finding.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [params.id, params.key]);

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertTitle>Could not load that finding</AlertTitle>
        <AlertDescription>
          {error} It may belong to an installation this account cannot see, or to a different
          audit — a finding key is unique within one run, not across runs.
        </AlertDescription>
      </Alert>
    );
  }

  if (!detail) {
    return (
      <div className="flex flex-col gap-3">
        <Skeleton className="h-8 w-80" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  const { finding, unit } = detail;
  const calibration = toCalibration(detail.calibration);
  const combined = detail.witnesses.reduce((product, item) => product * item.likelihood_ratio, 1);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <Link
          href={`/audits/${detail.audit_id}`}
          className="text-muted-foreground text-sm hover:underline"
        >
          ← {detail.repository_full_name} #{detail.pr_number}
        </Link>
        <h1 className="mt-1 text-2xl font-semibold tracking-tight">
          {finding.title || `${finding.cwe} in ${finding.qualified_symbol}`}
        </h1>
        <p className="text-muted-foreground font-mono text-xs break-all">
          {finding.file}
          {finding.line_numbers.length > 0 && `:${finding.line_numbers.join(", ")}`} ·{" "}
          {finding.qualified_symbol} · {finding.finding_key}
        </p>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-6">
          <div className="min-w-0">
            <CardTitle className="text-base">
              {finding.cwe} — {CWE_TITLES[finding.cwe as Cwe] ?? "Out-of-scope weakness"}
            </CardTitle>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <Badge variant="secondary" className="font-mono">
                {finding.severity}
              </Badge>
              {finding.is_alert_worthy && <Badge variant="destructive">alert</Badge>}
            </div>
            {finding.consensus_rationale && (
              <p className="mt-3 text-sm">{finding.consensus_rationale}</p>
            )}
          </div>
          <Posterior
            value={finding.posterior_probability}
            calibration={calibration}
            threshold={finding.alert_threshold}
            size="large"
          />
        </CardHeader>
      </Card>

      <section className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold tracking-tight">How the odds moved</h2>
        <p className="text-muted-foreground text-sm">
          One factor per witness, always four, whatever the agents said. A witness that could not
          look contributes exactly 1.0 — it does not get to vote the code innocent, and it does not
          get to convict it either.
        </p>

        {detail.contributions_recorded ? (
          <Card>
            <CardContent className="flex flex-col gap-4 py-4">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-2 font-mono text-sm">
                <Factor
                  label="prior odds"
                  value={odds(finding.prior_probability)}
                  hint={`A declared base rate of ${(finding.prior_probability * 100).toFixed(1)}%, not measured from the corpus — a twin-paired corpus is 50% vulnerable by construction (D-083).`}
                />
                {detail.witnesses.map((item) => (
                  <span key={item.witness} className="flex items-center gap-3">
                    <span className="text-muted-foreground">×</span>
                    <Factor
                      label={item.witness}
                      value={item.likelihood_ratio}
                      hint={
                        item.cell
                          ? `Read from the ${item.cell} cell of this witness's fitted ratios.`
                          : "No cell: this witness abstained, or said nothing about this weakness. Exactly 1.0 by definition, never a fitted number."
                      }
                    />
                  </span>
                ))}
              </div>
              <Separator />
              <p className="text-muted-foreground text-xs">
                The four ratios multiply to{" "}
                <span className="text-foreground font-mono">{combined.toFixed(3)}×</span>. Applied
                to the prior odds above, that is the posterior shown at the top of this page — read
                from the row this run wrote, not recomputed here. A ratio is only as good as the
                cell it came from; the{" "}
                <Link href="/calibration" className="underline">
                  calibration page
                </Link>{" "}
                shows how many observations sit behind each one.
              </p>
            </CardContent>
          </Card>
        ) : (
          <Alert>
            <AlertTitle>The breakdown was not recorded for this finding</AlertTitle>
            <AlertDescription>
              It was written before CodeSheriff stored the factors of the odds product. The
              statements below are on the record and are shown in full; the ratios are not, and are
              deliberately left blank rather than drawn as four neutral factors. An unrecorded ratio
              and a witness that contributed nothing are different claims, and only one of them was
              made by this run.
            </AlertDescription>
          </Alert>
        )}
      </section>

      <section className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold tracking-tight">What each witness said</h2>
        {detail.witnesses.map((item) => (
          <Witness key={item.witness} breakdown={item} recorded={detail.contributions_recorded} />
        ))}
      </section>

      {unit && (
        <section className="flex flex-col gap-3">
          <h2 className="text-lg font-semibold tracking-tight">The function analysed</h2>
          <Card>
            <CardContent className="flex flex-col gap-2 py-4 text-sm">
              <p className="font-mono break-all">
                {unit.file}:{unit.start_line} · {unit.qualified_symbol}
              </p>
              <div className="flex flex-wrap items-center gap-2">
                {unit.is_test_file && <Badge variant="outline">test file</Badge>}
                {unit.decorators.map((decorator) => (
                  <Badge key={decorator} variant="outline" className="font-mono text-[10px]">
                    @{decorator}
                  </Badge>
                ))}
                <span className="text-muted-foreground text-xs">
                  {unit.language} · {unit.post_src_lines} lines · {unit.changed_lines.length}{" "}
                  changed
                </span>
              </div>
              <p className="text-muted-foreground text-xs">
                The source itself is not stored. CodeSheriff keeps hashes, line metadata and what
                the witnesses said about them — never the body of the function (§6, D-027).
              </p>
            </CardContent>
          </Card>
        </section>
      )}
    </div>
  );
}

/** Prior probability as odds, which is the form the factors multiply. */
function odds(probability: number): number {
  const bounded = Math.min(0.999, Math.max(0.001, probability));
  return bounded / (1 - bounded);
}

function Factor({ label, value, hint }: { label: string; value: number; hint: string }) {
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <span className="flex cursor-help flex-col">
            <span className="tabular-nums">{value.toFixed(3)}</span>
            <span className="text-muted-foreground text-[10px]">{label}</span>
          </span>
        }
      />
      <TooltipContent className="max-w-xs">{hint}</TooltipContent>
    </Tooltip>
  );
}

/**
 * One witness: its factor, and every statement its backends made.
 *
 * A neutral witness with an abstention under it is the case this section exists for. The odds did
 * not move, and the reason they did not move is that nobody could look — which is a different
 * sentence from "nothing was found", and the page has to be able to say both.
 */
function Witness({ breakdown, recorded }: { breakdown: WitnessBreakdown; recorded: boolean }) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4 pb-3">
        <div className="min-w-0">
          <CardTitle className="text-sm font-medium capitalize">{breakdown.witness}</CardTitle>
          <p className="text-muted-foreground mt-1 font-mono text-xs">
            {breakdown.agent_ids.length > 0
              ? breakdown.agent_ids.join(", ")
              : "no backend spoke for this witness"}
          </p>
          {breakdown.note && (
            <p className="text-muted-foreground mt-1 text-xs">{breakdown.note}</p>
          )}
        </div>
        <div className="flex flex-col items-end">
          {recorded ? (
            <>
              <span className="font-mono text-lg font-semibold tabular-nums">
                {breakdown.likelihood_ratio.toFixed(2)}×
              </span>
              <span className="text-muted-foreground font-mono text-[10px]">
                {breakdown.cell ?? "no cell — 1.0 by definition"}
              </span>
            </>
          ) : (
            <span className="text-muted-foreground text-xs">ratio not recorded</span>
          )}
        </div>
      </CardHeader>
      <Separator />
      <CardContent className="flex flex-col gap-4 pt-3">
        {breakdown.statements.length === 0 ? (
          <p className="text-muted-foreground text-sm">
            This witness emitted no statement at all. That should not happen — an agent that cannot
            run is expected to abstain under its own name — and it is shown rather than hidden.
          </p>
        ) : (
          breakdown.statements.map((statement, index) => (
            <Statement key={`${statement.agent_id}-${index}`} evidence={statement} />
          ))
        )}
      </CardContent>
    </Card>
  );
}

function Statement({ evidence }: { evidence: EvidenceDetail }) {
  const label = AGENT_LABELS[evidence.agent_id as AgentId] ?? evidence.agent_id;
  return (
    <div className="flex flex-col gap-2">
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
          — and nothing else. A silence about CWEs this finding is not about carries no weight.
        </p>
      )}
      {evidence.kind === "abstention" && evidence.reason && (
        <p className="text-muted-foreground font-mono text-xs">reason: {evidence.reason}</p>
      )}
      {evidence.artifacts.map((artifact, index) => (
        <ArtifactView key={`${artifact.artifact_type}-${index}`} artifact={artifact} />
      ))}
    </div>
  );
}

interface TaintStep {
  line: number;
  expr: string;
  var_name: string;
  role: string;
}

/**
 * A witness showing its work.
 *
 * The taint path gets a renderer of its own because it is the one artifact that is an argument
 * rather than a note: an ordered flow from an untrusted source to a dangerous sink, which a reader
 * can follow and disagree with. Everything else is printed as the JSON the agent produced —
 * unglamorous, but it never silently drops a field an agent started emitting.
 *
 * All of this quotes code from the pull request, which is authored by whoever opened it. It is
 * rendered as text; nothing here goes near `dangerouslySetInnerHTML`.
 */
function ArtifactView({ artifact }: { artifact: { artifact_type: string; content: unknown } }) {
  if (artifact.artifact_type === "taint_path") {
    const content = artifact.content as { steps?: TaintStep[]; sink_class?: string };
    const steps = content.steps ?? [];
    if (steps.length > 0) {
      return (
        <div className="bg-muted/40 flex flex-col gap-1 rounded-md border p-3">
          <p className="text-muted-foreground text-xs">
            Taint path{content.sink_class ? ` to a ${content.sink_class} sink` : ""} —{" "}
            {steps.length} step{steps.length === 1 ? "" : "s"}
          </p>
          <ol className="flex flex-col gap-1">
            {steps.map((step, index) => (
              <li key={index} className="flex items-baseline gap-2 font-mono text-xs">
                <span className="text-muted-foreground w-12 shrink-0 tabular-nums">
                  :{step.line}
                </span>
                <Badge variant="outline" className="shrink-0 text-[10px]">
                  {step.role}
                </Badge>
                <span className="break-all">{step.expr}</span>
              </li>
            ))}
          </ol>
        </div>
      );
    }
  }

  return (
    <details className="bg-muted/40 rounded-md border p-3">
      <summary className="text-muted-foreground cursor-pointer text-xs">
        {artifact.artifact_type}
      </summary>
      <pre className="mt-2 overflow-x-auto text-xs">
        {JSON.stringify(artifact.content, null, 2)}
      </pre>
    </details>
  );
}
