"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { FolderGit2, Globe, Lock, Search } from "lucide-react";
import { toast } from "sonner";

import { buttonVariants } from "@/components/chai/button";
import { Chip } from "@/components/chai/chip";
import { Highlight } from "@/components/chai/highlight";
import { PageHeader } from "@/components/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import { listRepositories, setAnalysisEnabled, type RepositoryOut } from "@/lib/api";
import { cn } from "@/lib/utils";

type FilterMode = "all" | "active" | "private" | "public";

export default function RepositoriesPage() {
  const [items, setItems] = useState<RepositoryOut[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [exhausted, setExhausted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadedOnce, setLoadedOnce] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<Set<number>>(new Set());
  const [searchQuery, setSearchQuery] = useState("");
  const [filterMode, setFilterMode] = useState<FilterMode>("all");
  const sentinel = useRef<HTMLDivElement | null>(null);

  const loadMore = useCallback(async (fromCursor: string | null) => {
    setLoading(true);
    setError(null);
    try {
      const page = await listRepositories(fromCursor);
      setItems((current) => {
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
  }, []);

  useEffect(() => {
    const node = sentinel.current;
    if (!node || exhausted || loading) return;

    const observer = new IntersectionObserver((entries) => {
      if (entries[0]?.isIntersecting) void loadMore(cursor);
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, [cursor, exhausted, loading, loadMore]);

  async function toggle(repo: RepositoryOut) {
    const nextState = !repo.analysis_enabled;
    setPending((current) => new Set(current).add(repo.id));

    // Optimistic update
    setItems((current) =>
      current.map((row) => (row.id === repo.id ? { ...row, analysis_enabled: nextState } : row)),
    );

    try {
      const updated = await setAnalysisEnabled(repo.id, nextState);
      setItems((current) => current.map((row) => (row.id === updated.id ? updated : row)));
      if (nextState) {
        toast.success(`Analysis on for ${repo.full_name}`, {
          description: "New pull requests on this repository will be audited.",
        });
      } else {
        toast.info(`Analysis off for ${repo.full_name}`);
      }
    } catch (caught) {
      setItems((current) => current.map((row) => (row.id === repo.id ? repo : row)));
      const msg = caught instanceof Error ? caught.message : "Could not change repository status.";
      setError(msg);
      toast.error("Failed to update repository", { description: msg });
    } finally {
      setPending((current) => {
        const next = new Set(current);
        next.delete(repo.id);
        return next;
      });
    }
  }

  // Filtered view
  const filteredItems = useMemo(() => {
    return items.filter((repo) => {
      const matchesSearch =
        searchQuery.trim() === "" ||
        repo.full_name.toLowerCase().includes(searchQuery.toLowerCase());

      if (!matchesSearch) return false;

      if (filterMode === "active") return repo.analysis_enabled;
      if (filterMode === "private") return repo.is_private;
      if (filterMode === "public") return !repo.is_private;
      return true;
    });
  }, [items, searchQuery, filterMode]);

  const activeCount = useMemo(() => items.filter((r) => r.analysis_enabled).length, [items]);

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        title="Repositories"
        action={
          <Link href="/github-app" className={buttonVariants({ variant: "outline" })}>
            Manage on the GitHub App page
          </Link>
        }
      >
        Where the GitHub App is installed. Turn analysis on and{" "}
        <Highlight>every pull request</Highlight> gets an audit. {activeCount} of {items.length} are
        on.
      </PageHeader>

      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <label className="relative w-full sm:w-80">
          <span className="sr-only">Search repositories</span>
          <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
          <input
            type="search"
            placeholder="Search repositories"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-9 w-full rounded-md border border-input bg-transparent pr-3 pl-9 text-sm outline-none placeholder:text-muted-foreground focus-visible:ring-[3px] focus-visible:ring-ring/50"
          />
        </label>

        <div role="group" aria-label="Filter repositories" className="flex w-fit overflow-hidden rounded-md border border-border">
          {FILTERS.map(({ value, label }) => (
            <button
              key={value}
              type="button"
              onClick={() => setFilterMode(value)}
              aria-pressed={filterMode === value}
              className={cn(
                "h-8 cursor-pointer px-3 text-sm transition-colors duration-200 outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
                filterMode === value
                  ? "bg-orange-100 text-orange-900 dark:bg-orange-900/40 dark:text-orange-100"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTitle>Something went wrong</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {items.length === 0 && loadedOnce && !loading && !error && (
        <Alert>
          <AlertTitle>Connect the GitHub App first</AlertTitle>
          <AlertDescription className="flex flex-col items-start gap-3">
            <span>
              Repositories appear here once the GitHub App is installed and granted access to
              them.
            </span>
            <Link href="/github-app" className={buttonVariants({ variant: "soft", size: "sm" })}>
              Go to the GitHub App page
            </Link>
          </AlertDescription>
        </Alert>
      )}

      {filteredItems.length > 0 && (
        <div className="card-chai overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Repository</TableHead>
                <TableHead className="hidden sm:table-cell">Default branch</TableHead>
                <TableHead className="pr-4 text-right">Analysis</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredItems.map((repo) => (
                <TableRow key={repo.id}>
                  {/* Wraps on a phone: a long owner/name plus its chip would otherwise scroll the table. */}
                  <TableCell className="whitespace-normal">
                    <div className="flex flex-wrap items-center gap-2">
                      <FolderGit2 className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                      <span className="font-medium break-all">{repo.full_name}</span>
                      <Chip>
                        {repo.is_private ? <Lock className="size-2.5" aria-hidden="true" /> : <Globe className="size-2.5" aria-hidden="true" />}
                        {repo.is_private ? "private" : "public"}
                      </Chip>
                    </div>
                  </TableCell>
                  <TableCell className="hidden font-mono text-xs text-muted-foreground sm:table-cell">
                    {repo.default_branch}
                  </TableCell>
                  {/* pr-4 contains the switch's enlarged tap area, which reaches 12px past its edge. */}
                  <TableCell className="pr-4 text-right">
                    <div className="flex items-center justify-end gap-3">
                      <span className={cn("text-xs", repo.analysis_enabled ? "text-green-700 dark:text-green-400" : "text-muted-foreground")}>
                        {repo.analysis_enabled ? "On" : "Off"}
                      </span>
                      <Switch
                        checked={repo.analysis_enabled}
                        disabled={pending.has(repo.id)}
                        onCheckedChange={() => void toggle(repo)}
                        aria-label={`Analyse ${repo.full_name}`}
                      />
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {loading && <Skeleton className="h-10 w-full" />}
      <div ref={sentinel} aria-hidden className="h-1" />
    </div>
  );
}

const FILTERS: { value: FilterMode; label: string }[] = [
  { value: "all", label: "All" },
  { value: "active", label: "On" },
  { value: "private", label: "Private" },
  { value: "public", label: "Public" },
];
