"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { getCalibration, type CalibrationResponse } from "@/lib/api";
import { AGENT_LABELS, CWE_TITLES, IN_SCOPE_CWES, type AgentId } from "@/lib/types";

/**
 * Settings — and the reasons most of this page is not editable.
 *
 * Chapter 15's original outline called for a per-repository alert threshold, per-repository agent
 * toggles and a per-repository CWE scope. All three were dropped, and the conflict is recorded as
 * D-089.
 *
 * The threshold is selected on the validation split and travels in the fitted artifact with the
 * corpus hash it was measured against. An operator who could raise it from this page could make a
 * calibrated system uncalibrated without changing a line of code or leaving a trace — and every
 * audit records the calibration run it was opened under precisely so that what it ran under stays
 * knowable afterwards. The agent roster is the same argument one level up: the ratios were fitted
 * over four witnesses, and switching one off would leave the fitted numbers describing a system
 * that is not the one running.
 *
 * The one setting that is genuinely a preference — whether CodeSheriff analyses a repository at
 * all — lives on the repositories page, where it already works.
 */
export default function SettingsPage() {
  const [data, setData] = useState<CalibrationResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getCalibration()
      .then((response) => !cancelled && setData(response))
      .catch((caught: unknown) => {
        if (!cancelled) {
          setError(caught instanceof Error ? caught.message : "Could not read the calibration.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-muted-foreground text-sm">
          What this deployment analyses, and what it decides with. Most of it is fixed on purpose.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Alert threshold</CardTitle>
          <CardDescription>Selected on the validation split. Not editable here.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 text-sm">
          {error && (
            <Alert variant="destructive">
              <AlertTitle>No fitted artifact</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {!data && !error && <Skeleton className="h-8 w-40" />}
          {data && (
            <>
              <span className="font-mono text-3xl font-semibold tabular-nums">
                {(data.artifact.threshold.value * 100).toFixed(1)}%
              </span>
              <p className="text-muted-foreground">
                Chosen by {data.artifact.threshold.objective} over the whole sweep on the{" "}
                {data.artifact.threshold.selected_on} split, and carried in the fitted artifact
                alongside the corpus hash it was measured against. A threshold an operator could
                raise from a settings page would make a calibrated system uncalibrated without
                leaving a trace, and every past audit records the numbers it actually ran under so
                that it cannot.
              </p>
              <Link href="/calibration" className="underline underline-offset-4">
                See the sweep it was chosen from →
              </Link>
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Witnesses</CardTitle>
          <CardDescription>
            Four independent bases for a decision. Fixed, and fusion iterates all of them.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 text-sm">
          {data ? (
            <>
              <div className="flex flex-col gap-2">
                {data.witnesses.map(({ witness, agents }) => (
                  <div key={witness} className="flex flex-wrap items-center gap-2">
                    <span className="w-24 font-medium">{witness}</span>
                    {agents.map((agent) => (
                      <Badge key={agent} variant="secondary" className="font-mono text-xs">
                        {AGENT_LABELS[agent as AgentId] ?? agent}
                      </Badge>
                    ))}
                  </div>
                ))}
              </div>
              <p className="text-muted-foreground">
                Backends are grouped under the witness they speak for, not listed as peers: two
                rule-based analyses of the same source text are one witness, and fusing them as two
                would multiply one piece of evidence in twice. Turning a witness off per repository
                would leave the fitted ratios describing a system that is not the one running,
                which is why there is no switch here. An agent that cannot run on a given machine
                abstains under its own name instead, at a likelihood ratio of exactly 1.0.
              </p>
            </>
          ) : (
            !error && <Skeleton className="h-24 w-full" />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Weakness scope</CardTitle>
          <CardDescription>A closed set of ten. Changed by a migration, not a toggle.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div className="flex flex-wrap gap-2">
            {IN_SCOPE_CWES.map((cwe) => (
              <Badge key={cwe} variant="secondary" className="gap-2 py-1">
                <span className="font-mono text-xs">{cwe}</span>
                <span className="text-muted-foreground text-xs">{CWE_TITLES[cwe]}</span>
              </Badge>
            ))}
          </div>
          <p className="text-muted-foreground text-sm">
            Every fitted number was measured against exactly this set, and the database enforces it
            as a constraint generated from the same contract. Widening it invalidates the fit,
            which is the right amount of friction for that decision — and narrowing it per
            repository would quietly change what the recall figures mean.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Per-repository analysis</CardTitle>
          <CardDescription>The one setting that is a preference.</CardDescription>
        </CardHeader>
        <CardContent className="text-sm">
          <p className="text-muted-foreground">
            Whether CodeSheriff analyses a repository at all is a switch on the{" "}
            <Link href="/repositories" className="underline underline-offset-4">
              repositories page
            </Link>
            . Removing its access entirely is done on GitHub, by uninstalling the App — an API that
            could uninstall itself would need a permission this App deliberately does not request.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
