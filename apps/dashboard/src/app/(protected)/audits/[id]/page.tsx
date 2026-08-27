import Link from "next/link";
import { notFound } from "next/navigation";

import { ChapterPlaceholder } from "@/components/chapter-placeholder";
import { Posterior } from "@/components/posterior";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { findAudit } from "@/lib/mock-data";
import { CWE_TITLES } from "@/lib/types";

export default async function AuditPage(props: PageProps<"/audits/[id]">) {
  const { id } = await props.params;
  const audit = findAudit(id);
  if (!audit) notFound();

  return (
    <div className="flex flex-col gap-6">
      <div>
        <Link href="/audits" className="text-muted-foreground text-sm hover:underline">
          ← Audits
        </Link>
        <h1 className="mt-1 text-2xl font-semibold tracking-tight">
          #{audit.prNumber} {audit.prTitle}
        </h1>
        <p className="text-muted-foreground font-mono text-xs">
          {audit.repositoryFullName} · {audit.headSha} · {audit.unitsAnalysed} units
        </p>
      </div>

      {audit.findings.length === 0 ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">No findings</CardTitle>
          </CardHeader>
          <CardContent className="text-muted-foreground text-sm">
            {audit.status === "failed"
              ? "This audit failed before it produced evidence. A failed audit is not a clean bill of health."
              : "Every agent that ran reported silence on the CWEs it covers."}
          </CardContent>
        </Card>
      ) : (
        <div className="flex flex-col gap-3">
          {audit.findings.map((finding) => (
            <Card key={finding.findingKey}>
              <CardHeader className="flex flex-row items-start justify-between gap-4">
                <div className="min-w-0">
                  <CardTitle className="text-base">
                    <Link href={`/findings/${finding.findingKey}`} className="hover:underline">
                      {finding.title}
                    </Link>
                  </CardTitle>
                  <p className="text-muted-foreground mt-1 font-mono text-xs">
                    {finding.file}:{finding.lineNumbers.join(", ")} · {finding.qualifiedSymbol}
                  </p>
                  <div className="mt-2 flex flex-wrap items-center gap-2">
                    <Badge variant="secondary">{finding.cwe}</Badge>
                    <span className="text-muted-foreground text-xs">
                      {CWE_TITLES[finding.cwe]}
                    </span>
                    {finding.isAlertWorthy && <Badge variant="destructive">alert</Badge>}
                  </div>
                </div>
                <Posterior
                  value={finding.posterior}
                  calibration={audit.calibration}
                  threshold={finding.alertThreshold}
                />
              </CardHeader>
            </Card>
          ))}
        </div>
      )}

      <ChapterPlaceholder chapter="Chapter 15" title="Audit detail">
        Change units, agent timings, cost per unit, and the verdict summary. The posteriors above
        come from fixtures and are marked provisional because no calibration artifact exists yet.
      </ChapterPlaceholder>
    </div>
  );
}
