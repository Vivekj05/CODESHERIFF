"use client";

import { ExternalLink, Plus } from "lucide-react";
import { useEffect, useState } from "react";

import { buttonVariants } from "@/components/chai/button";
import { Chip } from "@/components/chai/chip";
import { Highlight } from "@/components/chai/highlight";
import { GitHubMark } from "@/components/github-mark";
import { PageHeader } from "@/components/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { listInstallations, type InstallationList, type InstallationOut } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * Connecting the GitHub App (D-102). Signing in says who you are; this page decides which
 * repositories CodeSheriff may read.
 *
 * Every GitHub action here is a link to GitHub's own pages. Installing happens on GitHub's install
 * screen, which returns through sign-in so the new installation is in the token; managing and
 * disconnecting happen on the installation's settings page, where GitHub decides who may do it.
 * Disconnecting hides this installation's history rather than deleting it.
 */
const CAPABILITIES = [
  "Read code and pull requests on the repositories you select",
  "Receive pull request events, so every new commit is audited",
  "Post one summary comment, and suggested fixes, on each pull request",
  "Never push, commit or merge anything",
];

export default function GitHubAppPage() {
  const [data, setData] = useState<InstallationList | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    listInstallations()
      .then((response) => !cancelled && setData(response))
      .catch((caught: unknown) => {
        if (!cancelled) setError(caught instanceof Error ? caught.message : "Could not load.");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="flex flex-col gap-8">
      <PageHeader title="GitHub App">
        Install or disconnect the reviewer app. It only ever sees{" "}
        <Highlight>the repositories you choose</Highlight>.
      </PageHeader>

      {error && (
        <Alert variant="destructive">
          <AlertTitle>Could not read your installations</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {!data && !error && <Skeleton className="h-64 w-full" />}

      {data && data.items.length === 0 && <NotConnected installUrl={data.install_url} />}

      {data &&
        data.items.map((installation) => (
          <Connected key={installation.id} installation={installation} />
        ))}

      {data && data.items.length > 0 && data.install_url && (
        <a
          href={data.install_url}
          className="inline-flex w-fit items-center gap-1.5 text-sm text-muted-foreground transition-colors duration-200 hover:text-brand"
        >
          <Plus className="size-4" aria-hidden="true" />
          Install on another account or organisation
        </a>
      )}
    </div>
  );
}

function AppCard({
  status,
  children,
  footer,
}: {
  status: React.ReactNode;
  children: React.ReactNode;
  footer: React.ReactNode;
}) {
  return (
    <section className="card-chai flex flex-col">
      <div className="flex flex-col gap-5 p-6">
        <div className="flex items-start gap-3">
          <span className="flex size-10 shrink-0 items-center justify-center rounded-lg border border-card-edge">
            <GitHubMark className="size-5" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="font-montserrat text-base font-semibold">GitHub App</h2>
              {status}
            </div>
            <p className="text-sm text-muted-foreground">
              Install the CodeSheriff app on your GitHub account or organisation to give it access to
              public and private repositories.
            </p>
          </div>
        </div>
        {children}
      </div>
      <div className="flex flex-wrap items-center gap-3 border-t border-card-edge p-4">{footer}</div>
    </section>
  );
}

function Capabilities() {
  return (
    <ul className="flex flex-col gap-1.5 text-sm text-muted-foreground">
      {CAPABILITIES.map((item) => (
        <li key={item} className="flex gap-2">
          <span aria-hidden="true">·</span>
          {item}
        </li>
      ))}
    </ul>
  );
}

function NotConnected({ installUrl }: { installUrl: string | null }) {
  return (
    <AppCard
      status={<Chip className="shrink-0">Not connected</Chip>}
      footer={
        installUrl ? (
          <a href={installUrl} className={buttonVariants({ variant: "solid" })}>
            <GitHubMark />
            Install GitHub App
          </a>
        ) : (
          <p className="text-sm text-muted-foreground">
            This deployment has no GITHUB_APP_SLUG, so it cannot link to the App&apos;s install
            page.
          </p>
        )
      }
    >
      <Capabilities />
      <p className="text-xs text-muted-foreground">
        GitHub asks which repositories to grant. After installing you come straight back here.
      </p>
    </AppCard>
  );
}

function Connected({ installation }: { installation: InstallationOut }) {
  const since = new Date(installation.connected_at).toLocaleDateString(undefined, {
    day: "numeric",
    month: "long",
    year: "numeric",
  });
  const repos = installation.repository_count;
  const kind = installation.account_type === "Organization" ? "organisation" : "personal account";

  return (
    <AppCard
      status={
        installation.suspended ? (
          <Chip tone="danger" className="shrink-0">
            Suspended
          </Chip>
        ) : (
          <Chip tone="success" className="shrink-0">
            Connected
          </Chip>
        )
      }
      footer={
        <>
          <a
            href={installation.manage_url}
            target="_blank"
            rel="noreferrer"
            className={buttonVariants({ variant: "outline" })}
          >
            Manage repositories
            <ExternalLink className="-ml-1" aria-hidden="true" />
          </a>
          <a
            href={installation.manage_url}
            target="_blank"
            rel="noreferrer"
            className={cn(
              buttonVariants({ variant: "ghost" }),
              "text-red-700 hover:text-red-700 dark:text-red-400 dark:hover:text-red-400",
            )}
          >
            Disconnect GitHub App
            <ExternalLink className="-ml-1" aria-hidden="true" />
          </a>
        </>
      }
    >
      <p className="text-sm">
        Installed for{" "}
        <a
          href={`https://github.com/${installation.account_login}`}
          target="_blank"
          rel="noreferrer"
          className="font-medium underline-offset-4 hover:text-brand hover:underline"
        >
          @{installation.account_login}
        </a>
        <span className="text-muted-foreground">
          {" "}
          · {kind} · {repos} {repos === 1 ? "repository" : "repositories"} · connected {since}
        </span>
      </p>
      <Capabilities />
      <p className="text-xs text-muted-foreground">
        Both buttons open GitHub&apos;s settings for this installation; uninstall is at the bottom
        of that page. Disconnecting hides this installation&apos;s audits rather than deleting
        them, and they come back if you connect the same repositories again.
      </p>
    </AppCard>
  );
}
