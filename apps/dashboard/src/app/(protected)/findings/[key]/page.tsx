import Link from "next/link";
import { notFound } from "next/navigation";

import { ChapterPlaceholder } from "@/components/chapter-placeholder";
import { EvidenceKindBadge } from "@/components/evidence-kind-badge";
import { Posterior } from "@/components/posterior";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { findFinding } from "@/lib/mock-data";
import { AGENT_LABELS, CWE_TITLES } from "@/lib/types";

export default async function FindingPage(props: PageProps<"/findings/[key]">) {
  const { key } = await props.params;
  const match = findFinding(key);
  if (!match) notFound();

  const { audit, finding } = match;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <Link href={`/audits/${audit.id}`} className="text-muted-foreground text-sm hover:underline">
          ← #{audit.prNumber} {audit.prTitle}
        </Link>
        <h1 className="mt-1 text-2xl font-semibold tracking-tight">{finding.title}</h1>
        <p className="text-muted-foreground font-mono text-xs">
          {finding.file}:{finding.lineNumbers.join(", ")} · {finding.qualifiedSymbol} ·{" "}
          {finding.findingKey}
        </p>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-6">
          <div>
            <CardTitle className="text-base">
              {finding.cwe} — {CWE_TITLES[finding.cwe]}
            </CardTitle>
            <p className="text-muted-foreground mt-1 text-sm">
              Prior {Math.round(finding.priorProbability * 100)}%, updated by{" "}
              {finding.evidence.length} agent statements.
            </p>
          </div>
          <Posterior
            value={finding.posterior}
            calibration={audit.calibration}
            threshold={finding.alertThreshold}
            size="large"
          />
        </CardHeader>
      </Card>

      <div className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold tracking-tight">Evidence</h2>
        <p className="text-muted-foreground text-sm">
          Every agent, including the ones that found nothing and the ones that could not run. An
          agent that could not look does not vote the code innocent, and silence only counts against
          the CWEs an agent can actually detect.
        </p>
        {finding.evidence.map((evidence, index) => (
          <Card key={`${evidence.agentId}-${index}`}>
            <CardHeader className="flex flex-row items-center justify-between gap-4 pb-3">
              <CardTitle className="text-sm font-medium">
                {AGENT_LABELS[evidence.agentId]}
                <span className="text-muted-foreground ml-2 font-mono text-xs">
                  {evidence.agentId} v{evidence.agentVersion}
                </span>
              </CardTitle>
              <EvidenceKindBadge kind={evidence.kind} />
            </CardHeader>
            <Separator />
            <CardContent className="pt-3 text-sm">
              <p>{evidence.explanation}</p>
              {evidence.kind === "silence" && evidence.coveredCwes.length > 0 && (
                <p className="text-muted-foreground mt-2 text-xs">
                  Covers:{" "}
                  {evidence.coveredCwes.map((cwe) => (
                    <Badge key={cwe} variant="outline" className="mr-1 font-mono text-[10px]">
                      {cwe}
                    </Badge>
                  ))}
                </p>
              )}
              {evidence.kind === "abstention" && evidence.reason && (
                <p className="text-muted-foreground mt-2 font-mono text-xs">
                  reason: {evidence.reason}
                </p>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      <ChapterPlaceholder chapter="Chapter 16" title="Finding detail, properly">
        Taint path rendering, the per-agent likelihood ratios that moved the odds, and the debate
        transcript where agents disagreed. The evidence above is fixture data.
      </ChapterPlaceholder>
    </div>
  );
}
