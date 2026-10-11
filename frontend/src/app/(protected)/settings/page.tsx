"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { LogOut } from "lucide-react";
import { useEffect, useState } from "react";

import { buttonVariants } from "@/components/chai/button";
import { Highlight } from "@/components/chai/highlight";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/chai/tabs";
import { GitHubMark } from "@/components/github-mark";
import { PageHeader } from "@/components/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { getCalibration, logout, type CalibrationResponse } from "@/lib/api";
import { authClient } from "@/lib/auth-client";
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
function AnalysisSettings() {
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
      <p className="text-sm text-muted-foreground">
        What this deployment analyses, and what it decides with. Most of it is{" "}
        <Highlight>fixed on purpose</Highlight>.
      </p>

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
            which is the right amount of friction for that decision, and narrowing it per
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
            . Removing its access entirely is done on GitHub, by uninstalling the App: an API that
            could uninstall itself would need a permission this App deliberately does not request.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

/**
 * Settings: who you are (from your GitHub sign-in) and what this deployment decides with.
 *
 * The profile is read from the dashboard's Better Auth session and is read-only on purpose: GitHub
 * is its source, and leaving Better Auth's update-user endpoint unused keeps the server-only fields
 * (D-101) out of reach of the browser. There is no subscription tab; billing is out of scope (§6).
 */
export default function SettingsPage() {
  return (
    <div className="flex flex-col gap-8">
      <PageHeader title="Settings">
        Your profile, and the parts of the analysis that are <Highlight>fixed on purpose</Highlight>.
      </PageHeader>
      <Tabs defaultValue="profile" className="flex flex-col gap-6">
        <TabsList variant="segmented" className="w-fit">
          <TabsTrigger value="profile">Profile</TabsTrigger>
          <TabsTrigger value="analysis">Analysis</TabsTrigger>
        </TabsList>
        <TabsContent value="profile">
          <ProfileSettings />
        </TabsContent>
        <TabsContent value="analysis">
          <AnalysisSettings />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function ProfileSettings() {
  const { data, isPending } = authClient.useSession();
  const router = useRouter();

  if (isPending) return <Skeleton className="h-64 w-full" />;
  if (!data) return null;

  const user = data.user as typeof data.user & { login?: string };
  const since = new Date(user.createdAt).toLocaleDateString(undefined, {
    day: "numeric",
    month: "long",
    year: "numeric",
  });

  async function signOut() {
    try {
      await logout();
    } finally {
      router.replace("/");
    }
  }

  return (
    <section aria-labelledby="profile-h" className="card-chai flex flex-col">
      <div className="flex flex-col gap-6 p-6">
        <div>
          <h2 id="profile-h" className="font-montserrat text-base font-semibold">
            Profile
          </h2>
          <p className="text-sm text-muted-foreground">Account information from your GitHub sign-in.</p>
        </div>

        <div className="flex items-center gap-4">
          {user.image ? (
            // A GitHub avatar URL; next/image would need GitHub's host allow-listed for no gain here.
            // eslint-disable-next-line @next/next/no-img-element
            <img src={user.image} alt="" className="size-14 rounded-full border border-card-edge" />
          ) : (
            <span className="flex size-14 items-center justify-center rounded-full border border-card-edge">
              <GitHubMark className="size-6" />
            </span>
          )}
          <div className="min-w-0">
            <p className="font-medium">{user.name}</p>
            <p className="truncate text-sm text-muted-foreground">{user.email}</p>
            <p className="text-xs text-muted-foreground">Member since {since}</p>
          </div>
        </div>

        <ReadOnlyField label="Display name" value={user.name} />
        <ReadOnlyField label="Email" value={user.email} />
        {user.login && (
          <div className="flex flex-col gap-1.5">
            <span className="text-sm font-medium">GitHub</span>
            <a
              href={`https://github.com/${user.login}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex w-fit items-center gap-2 text-sm underline-offset-4 hover:text-brand hover:underline"
            >
              <GitHubMark />@{user.login}
            </a>
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-card-edge p-4">
        <p className="text-xs text-muted-foreground">
          Profile details are managed by GitHub. Update them in your GitHub account settings.
        </p>
        <button type="button" onClick={() => void signOut()} className={buttonVariants({ variant: "ghost", size: "sm" })}>
          <LogOut aria-hidden="true" />
          Sign out
        </button>
      </div>
    </section>
  );
}

function ReadOnlyField({ label, value }: { label: string; value: string }) {
  const id = `field-${label.toLowerCase().replace(/\s+/g, "-")}`;
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      <input
        id={id}
        value={value}
        readOnly
        className="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm text-muted-foreground outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
      />
    </div>
  );
}
