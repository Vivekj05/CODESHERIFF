"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { getSession, listRepositories, setAnalysisEnabled, type RepositoryOut } from "@/lib/api";

/**
 * The repository list — the first page in this project that renders real data.
 *
 * Paged by the cursor the API returns rather than by page number: the API keys on `full_name`, so a
 * repository added by an installation event mid-scroll cannot make a page skip or repeat rows.
 *
 * The switch is "connect / disconnect" as this project means it — whether CodeSheriff analyses pull
 * requests on that repository. Removing its access entirely is done on GitHub, by uninstalling: an
 * API that could uninstall itself would need write access to the installation, which the App does
 * not request (D-034).
 */
export default function RepositoriesPage() {
  const [items, setItems] = useState<RepositoryOut[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [exhausted, setExhausted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadedOnce, setLoadedOnce] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<Set<number>>(new Set());
  const [installUrl, setInstallUrl] = useState<string | null>(null);
  const sentinel = useRef<HTMLDivElement | null>(null);

  const loadMore = useCallback(
    async (fromCursor: string | null) => {
      setLoading(true);
      setError(null);
      try {
        const page = await listRepositories(fromCursor);
        setItems((current) => {
          // De-duplicate by id: a repository can arrive twice if the list shifted between pages.
          const seen = new Set(current.map((repo) => repo.id));
          return [...current, ...page.items.filter((repo) => !seen.has(repo.id))];
        });
        setCursor(page.next_cursor);
        setExhausted(page.next_cursor === null);
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : "Could not load repositories.");
        setExhausted(true);
      } finally {
        setLoading(false);
        setLoadedOnce(true);
      }
    },
    [],
  );

  useEffect(() => {
    // Not `await`ed and not assigned: the install link is a nicety, and a session that has gone
    // away is the shell's problem, not this table's.
    getSession()
      .then((session) => setInstallUrl(session.install_url))
      .catch(() => setInstallUrl(null));
  }, []);

  useEffect(() => {
    const node = sentinel.current;
    if (!node || exhausted || loading) return;

    // The sentinel sits below the table, so it is already visible on an empty list — which makes
    // this the first page load as well as every subsequent one. One code path, and the fetch
    // starts from an observer callback rather than from the effect body.
    const observer = new IntersectionObserver((entries) => {
      if (entries[0]?.isIntersecting) void loadMore(cursor);
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, [cursor, exhausted, loading, loadMore]);

  async function toggle(repo: RepositoryOut) {
    setPending((current) => new Set(current).add(repo.id));
    // Optimistic, then reconciled with what the API actually stored — the server is the authority
    // on whether the change took.
    setItems((current) =>
      current.map((row) =>
        row.id === repo.id ? { ...row, analysis_enabled: !row.analysis_enabled } : row,
      ),
    );
    try {
      const updated = await setAnalysisEnabled(repo.id, !repo.analysis_enabled);
      setItems((current) => current.map((row) => (row.id === updated.id ? updated : row)));
    } catch (caught) {
      setItems((current) => current.map((row) => (row.id === repo.id ? repo : row)));
      setError(caught instanceof Error ? caught.message : "Could not change that repository.");
    } finally {
      setPending((current) => {
        const next = new Set(current);
        next.delete(repo.id);
        return next;
      });
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Repositories</h1>
        <p className="text-muted-foreground text-sm">
          Repositories this GitHub App installation can reach. Refreshed each time you sign in.
        </p>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTitle>Something went wrong</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {items.length === 0 && loadedOnce && !loading && !error && (
        <Alert>
          <AlertTitle>No repositories yet</AlertTitle>
          <AlertDescription className="flex flex-col items-start gap-3">
            <span>
              This account has no installation of the App, or the installation grants access to no
              repositories.
            </span>
            {installUrl && (
              <Button size="sm" render={<a href={installUrl}>Install on a repository</a>} />
            )}
          </AlertDescription>
        </Alert>
      )}

      {items.length > 0 && (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Repository</TableHead>
              <TableHead>Default branch</TableHead>
              <TableHead className="text-right">Analysis</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((repo) => (
              <TableRow key={repo.id}>
                <TableCell className="font-medium">
                  {repo.full_name}
                  {repo.is_private && (
                    <Badge variant="secondary" className="ml-2 text-xs">
                      private
                    </Badge>
                  )}
                </TableCell>
                <TableCell className="text-muted-foreground font-mono text-xs">
                  {repo.default_branch}
                </TableCell>
                <TableCell className="text-right">
                  <Switch
                    checked={repo.analysis_enabled}
                    disabled={pending.has(repo.id)}
                    onCheckedChange={() => void toggle(repo)}
                    aria-label={`Analyse ${repo.full_name}`}
                  />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      {loading && <Skeleton className="h-10 w-full" />}
      <div ref={sentinel} aria-hidden className="h-1" />
    </div>
  );
}
