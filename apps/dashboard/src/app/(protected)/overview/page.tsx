"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { Stat } from "@/components/stat";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { getCalibration, getOverview, type CalibrationResponse, type Overview } from "@/lib/api";
import { AGENT_LABELS, CWE_TITLES, type AgentId, type Cwe } from "@/lib/types";

/**
 * What this installation has actually analysed.
 *
 * Counts of things that happened, and deliberately no score. A single "security grade" would be
 * an uncalibrated number rendered in the same typeface as the calibrated ones, which is the
 * confusion this whole project argues against.
 *
 * The witness table is the part worth reading. It says how often each agent detected, stayed
 * silent and abstained *here* — and an agent abstaining on everything is not a quiet agent, it is
 * one that cannot run on this deployment. `structural.semgrep` on a host with no Semgrep build is
 * the standing example, and it belongs on the front page rather than being inferred from an empty
 * dashboard.
 */
export default function OverviewPage() {
  const [stats, setStats] = useState<Overview | null>(null);
  const [calibration, setCalibration] = useState<CalibrationResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getOverview()
      .then((data) => !cancelled && setStats(data))
      .catch((caught: unknown) => {
        if (!cancelled) {
          setError(caught instanceof Error ? caught.message : "Could not load the overview.");
        }
      });
    // Separate, and allowed to fail on its own: a deployment with no fitted artifact still has
    // audits worth showing, and the calibration card says what is missing in its own words.
    getCalibration()
      .then((data) => !cancelled && setCalibration(data))
      .catch(() => !cancelled && setCalibration(null));
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertTitle>Could not load the overview</AlertTitle>
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  if (!stats) {
    return (
      <div className="flex flex-col gap-3">
        <Skeleton className="h-8 w-56" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }

  const validation = calibration?.artifact.metrics.validation;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
        <p className="text-muted-foreground text-sm">
          Every number here is a count of something that happened. There is no aggregate score —
          the claim this project makes is about one posterior about one function.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat
          label="Repositories"
          value={stats.repositories}
          note={`${stats.repositories_analysing} with analysis on`}
        />
        <Stat
          label="Audits"
          value={stats.audits}
          note={
            stats.latest_audit_at
              ? `latest ${new Date(stats.latest_audit_at).toLocaleString()}`
              : "none yet"
          }
        />
        <Stat
          label="Functions analysed"
          value={stats.units_analysed}
          note="one change unit per changed function"
        />
        <Stat
          label="Alerts"
          value={stats.alerts}
          emphasis={stats.alerts > 0}
          note={`of ${stats.findings} finding${stats.findings === 1 ? "" : "s"} above threshold`}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Calibration in force</CardTitle>
        </CardHeader>
        <CardContent className="text-sm">
          {calibration ? (
            <div className="flex flex-col gap-2">
              <p>
                Ratios fitted on the calibration split of corpus{" "}
                <code className="font-mono text-xs">
                  {calibration.artifact.corpus_hash.slice(0, 12)}
                </code>
                ; alert threshold{" "}
                <span className="font-mono">
                  {(calibration.artifact.threshold.value * 100).toFixed(1)}%
                </span>{" "}
                selected on the validation split.
              </p>
              {validation && (
                <p className="text-muted-foreground">
                  Weighted ECE {validation.ece.toFixed(3)} and Brier {validation.brier.toFixed(3)}{" "}
                  over {validation.n_claims} validation claims. The honest figures are the test
                  split&rsquo;s, which stays sealed until the final evaluation.
                </p>
              )}
              <Link href="/calibration" className="text-sm underline underline-offset-4">
                What these numbers rest on →
              </Link>
            </div>
          ) : (
            <p className="text-muted-foreground">
              No fitted calibration artifact could be read, so this deployment cannot state how
              reliable its posteriors are. There is deliberately no fallback ratio table.
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">What each witness has said</CardTitle>
        </CardHeader>
        <CardContent>
          {stats.witnesses.length === 0 ? (
            <p className="text-muted-foreground text-sm">
              No agent has made a statement yet. Statements appear once an audit analyses a
              function.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Agent</TableHead>
                  <TableHead className="text-right">Detections</TableHead>
                  <TableHead className="text-right">Silences</TableHead>
                  <TableHead className="text-right">Abstentions</TableHead>
                  <TableHead>Reading</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {stats.witnesses.map((row) => {
                  const label = AGENT_LABELS[row.agent_id as AgentId] ?? row.agent_id;
                  const allAbstained = row.statements > 0 && row.abstentions === row.statements;
                  return (
                    <TableRow key={row.agent_id}>
                      <TableCell className="font-medium">
                        {label}
                        <span className="text-muted-foreground ml-2 font-mono text-xs">
                          {row.agent_id}
                        </span>
                      </TableCell>
                      <TableCell className="text-right font-mono tabular-nums">
                        {row.detections}
                      </TableCell>
                      <TableCell className="text-right font-mono tabular-nums">
                        {row.silences}
                      </TableCell>
                      <TableCell className="text-right font-mono tabular-nums">
                        {row.abstentions}
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs">
                        {allAbstained
                          ? "Never ran here — it costs the posterior nothing, and hides from nobody."
                          : "Ran, and its silences count only for the CWEs it covers."}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {stats.by_cwe.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Findings by weakness</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {stats.by_cwe.map((row) => (
              <Badge key={row.cwe} variant="secondary" className="gap-2 py-1">
                <span className="font-mono">{row.cwe}</span>
                <span className="text-muted-foreground">
                  {CWE_TITLES[row.cwe as Cwe] ?? "out of the recorded set"}
                </span>
                <span className="font-mono tabular-nums">
                  {row.alerts}/{row.findings}
                </span>
              </Badge>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
