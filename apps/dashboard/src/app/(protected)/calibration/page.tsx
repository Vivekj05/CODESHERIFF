"use client";

import { useEffect, useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
  ZAxis,
} from "recharts";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { getCalibration, type CalibrationResponse } from "@/lib/api";
import { AGENT_LABELS, type AgentId } from "@/lib/types";

/**
 * What the numbers rest on.
 *
 * This page is the project's thesis rendered. A tool that shows an 87% and nothing else is the
 * one this work argues against; the difference is entirely in what can be inspected behind the
 * number — the reliability bins the ECE was computed over, the observation counts behind every
 * likelihood ratio, the whole threshold sweep rather than the winning point, and the provenance
 * saying which backends were actually running when the observations were made.
 *
 * Three things on this page are deliberately unflattering, and they stay: a ratio held up by
 * smoothing shows its counts, a witness that abstained on almost everything shows how few claims
 * it was fitted from, and the base rate says it was declared rather than measured.
 *
 * Nothing here is computed in the browser. Every value is read from `calibration.json` as the API
 * served it — a dashboard that recalculated an ECE would be a second implementation whose
 * agreement with the first nobody checks.
 */
const CELL_LABELS: Record<string, string> = {
  detection_high: "Detection (score ≥ 0.8)",
  detection_medium: "Detection (0.5–0.8)",
  detection_low: "Detection (< 0.5)",
  silence: "Silence",
};

export default function CalibrationPage() {
  const [data, setData] = useState<CalibrationResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getCalibration()
      .then((response) => !cancelled && setData(response))
      .catch((caught: unknown) => {
        if (!cancelled) {
          setError(caught instanceof Error ? caught.message : "Could not load the calibration.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertTitle>No calibration artifact</AlertTitle>
        <AlertDescription>
          {error} There is deliberately no fallback ratio table: a deployment that cannot load its
          fitted numbers reports that, rather than producing numbers nobody measured.
        </AlertDescription>
      </Alert>
    );
  }

  if (!data) {
    return (
      <div className="flex flex-col gap-3">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  const { artifact } = data;
  const validation = artifact.metrics.validation;
  const calibrationSplit = artifact.metrics.calibration;
  const bins = (validation?.bins ?? []).filter((bin) => bin.n > 0);
  const sweep = artifact.threshold.sweep;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Calibration</h1>
        <p className="text-muted-foreground text-sm">
          A stated 87% should mean being right about 87% of the time. This page is the evidence for
          that correspondence — or for its absence.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Fact
          label="Alert threshold"
          value={`${(artifact.threshold.value * 100).toFixed(1)}%`}
          note={`${artifact.threshold.objective} on ${artifact.threshold.selected_on}`}
        />
        <Fact
          label="Base rate"
          value={`${(artifact.prior.base_rate * 100).toFixed(1)}%`}
          note={`${artifact.prior.source}, not measured`}
        />
        <Fact
          label="Weighted ECE"
          value={validation ? validation.ece.toFixed(3) : "—"}
          note={validation ? `${validation.n_claims} validation claims` : "not recorded"}
        />
        <Fact
          label="Brier"
          value={validation ? validation.brier.toFixed(3) : "—"}
          note={
            calibrationSplit
              ? `${calibrationSplit.brier.toFixed(3)} in-sample on calibration`
              : "not recorded"
          }
        />
      </div>

      <Alert>
        <AlertTitle>Read these as selection-time figures</AlertTitle>
        <AlertDescription>
          The ratios were fitted on the calibration split and the threshold selected on the
          validation split. The honest figures are the test split&rsquo;s, and it stays sealed
          until the final evaluation — it may be read exactly once.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Reliability</CardTitle>
          <CardDescription>
            Each point is a bin of validation claims: stated confidence across, observed frequency
            up, point size the number of claims in it. The dashed line is perfect calibration —
            below it the system is overconfident, above it under.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {bins.length === 0 ? (
            <p className="text-muted-foreground text-sm">No reliability bins were recorded.</p>
          ) : (
            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <ScatterChart margin={{ top: 8, right: 16, bottom: 24, left: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                  <XAxis
                    type="number"
                    dataKey="mean_confidence"
                    name="Stated confidence"
                    domain={[0, 1]}
                    tickFormatter={(value: number) => `${Math.round(value * 100)}%`}
                    fontSize={12}
                  />
                  <YAxis
                    type="number"
                    dataKey="observed_frequency"
                    name="Observed frequency"
                    domain={[0, 1]}
                    tickFormatter={(value: number) => `${Math.round(value * 100)}%`}
                    fontSize={12}
                  />
                  <ZAxis type="number" dataKey="n" range={[60, 400]} name="claims" />
                  <ReferenceLine
                    segment={[
                      { x: 0, y: 0 },
                      { x: 1, y: 1 },
                    ]}
                    stroke="currentColor"
                    strokeDasharray="4 4"
                    opacity={0.5}
                  />
                  <RechartsTooltip
                    formatter={(value, name) =>
                      typeof value === "number" && name !== "claims"
                        ? `${(value * 100).toFixed(1)}%`
                        : String(value ?? "")
                    }
                  />
                  <Scatter data={bins} fill="currentColor" fillOpacity={0.65} />
                </ScatterChart>
              </ResponsiveContainer>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">How the threshold was chosen</CardTitle>
          <CardDescription>
            The whole sweep on the validation split, not just the winner. A threshold whose
            neighbours score nearly as well was chosen from a flat surface, and that is worth
            seeing.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={sweep} margin={{ top: 8, right: 16, bottom: 24, left: 8 }}>
                <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                <XAxis
                  dataKey="threshold"
                  type="number"
                  domain={[0, 1]}
                  tickFormatter={(value: number) => `${Math.round(value * 100)}%`}
                  fontSize={12}
                />
                <YAxis domain={[0, 1]} fontSize={12} />
                <RechartsTooltip
                  labelFormatter={(label) =>
                    typeof label === "number"
                      ? `threshold ${(label * 100).toFixed(1)}%`
                      : String(label ?? "")
                  }
                  formatter={(value) =>
                    typeof value === "number" ? value.toFixed(3) : String(value ?? "")
                  }
                />
                <ReferenceLine
                  x={artifact.threshold.value}
                  stroke="currentColor"
                  strokeDasharray="4 4"
                  label={{ value: "selected", fontSize: 11, position: "top" }}
                />
                <Line type="monotone" dataKey="precision" dot={false} strokeWidth={2} />
                <Line
                  type="monotone"
                  dataKey="recall"
                  dot={false}
                  strokeWidth={2}
                  strokeDasharray="6 3"
                />
                <Line type="monotone" dataKey="f1" dot={false} strokeWidth={1} opacity={0.6} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <p className="text-muted-foreground mt-2 text-xs">
            Solid: precision. Dashed: recall. Thin: F1, the objective that selected the value.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Likelihood ratios, with their counts</CardTitle>
          <CardDescription>
            One row per cell. A ratio fitted from few observations is mostly the smoothing prior,
            and the counts are how you tell. A cell nobody selected contributes exactly 1.0 rather
            than a smoothed value — otherwise a never-observed tier would argue mildly for safety.
          </CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Witness</TableHead>
                <TableHead>Cell</TableHead>
                <TableHead className="text-right">LR</TableHead>
                <TableHead className="text-right">n vulnerable</TableHead>
                <TableHead className="text-right">n safe</TableHead>
                <TableHead>Notes</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.witnesses.flatMap(({ witness, agents }) => {
                const fit = artifact.fit.witnesses[witness];
                if (!fit) return [];
                return Object.entries(fit.cells).map(([cell, values], index) => (
                  <TableRow key={`${witness}-${cell}`}>
                    <TableCell className="align-top">
                      {index === 0 && (
                        <div className="flex flex-col gap-1">
                          <span className="font-medium">{witness}</span>
                          <span className="text-muted-foreground text-xs">
                            {agents.join(", ")}
                          </span>
                          <span className="text-muted-foreground text-xs">
                            {fit.n_vulnerable_claims + fit.n_safe_claims} claims ·{" "}
                            {fit.n_abstained} abstained
                          </span>
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="text-sm">{CELL_LABELS[cell] ?? cell}</TableCell>
                    <TableCell className="text-right font-mono tabular-nums">
                      {values.ratio.toFixed(2)}
                    </TableCell>
                    <TableCell className="text-right font-mono tabular-nums">
                      {values.n_vulnerable}
                    </TableCell>
                    <TableCell className="text-right font-mono tabular-nums">
                      {values.n_safe}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs">
                      {values.n_vulnerable + values.n_safe === 0
                        ? "never observed — contributes nothing"
                        : values.clamped
                          ? `clamped (raw ${values.raw_ratio.toFixed(2)})`
                          : ""}
                    </TableCell>
                  </TableRow>
                ));
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Provenance</CardTitle>
          <CardDescription>
            Which machine produced the observations, and which backends were actually running. A
            structural ratio fitted with no Semgrep build describes a one-backend witness — that is
            a property of the number, not a footnote about the machine.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4 text-sm">
          <div className="flex flex-wrap gap-2">
            <Badge variant="outline" className="font-mono text-xs">
              corpus {artifact.corpus_hash.slice(0, 12)}
            </Badge>
            <Badge variant="outline" className="font-mono text-xs">
              split {artifact.split_hash.slice(0, 12)}
            </Badge>
            <Badge variant="outline" className="font-mono text-xs">
              contract {artifact.contract_version}
            </Badge>
            <Badge variant="outline" className="font-mono text-xs">
              {data.source}
            </Badge>
          </div>
          {Object.entries(artifact.provenance).map(([split, run]) => (
            <div key={split} className="flex flex-col gap-1">
              <span className="font-medium">{split} split</span>
              <span className="text-muted-foreground font-mono text-xs">
                {run.platform} · python {run.python_version} · {run.generated}
              </span>
              {run.backends_silent.length > 0 && (
                <span className="text-xs">
                  Silent throughout:{" "}
                  {run.backends_silent.map((agent) => (
                    <Badge key={agent} variant="secondary" className="mr-1 font-mono text-[10px]">
                      {AGENT_LABELS[agent as AgentId] ?? agent}
                    </Badge>
                  ))}
                  — the ratios for its witness describe the backends that did run.
                </span>
              )}
              {run.semantic_source && (
                <span className="text-muted-foreground text-xs">
                  Semantic responses: {run.semantic_source}
                </span>
              )}
            </div>
          ))}
          <p className="text-muted-foreground text-xs">
            Base rate {(artifact.prior.base_rate * 100).toFixed(1)}% is {artifact.prior.source},
            rescaled from a corpus prevalence of{" "}
            {(artifact.prior.corpus_prevalence * 100).toFixed(0)}%.{" "}
            {artifact.prior.rationale ||
              "A twin-paired corpus is balanced by construction, so it cannot supply a prior."}
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

function Fact({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <Card>
      <CardContent className="flex flex-col gap-1 py-4">
        <span className="text-muted-foreground text-xs uppercase tracking-wide">{label}</span>
        <span className="font-mono text-2xl font-semibold tabular-nums">{value}</span>
        <span className="text-muted-foreground text-xs">{note}</span>
      </CardContent>
    </Card>
  );
}
