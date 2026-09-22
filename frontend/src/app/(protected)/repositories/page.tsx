"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  CheckCircle2,
  Database,
  ExternalLink,
  FolderGit2,
  Globe,
  Lock,
  Radio,
  Search,
  Webhook,
} from "lucide-react";
import { toast } from "sonner";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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

type FilterMode = "all" | "active" | "private" | "public";

export default function RepositoriesPage() {
  const [items, setItems] = useState<RepositoryOut[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [exhausted, setExhausted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadedOnce, setLoadedOnce] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<Set<number>>(new Set());
  const [installUrl, setInstallUrl] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [filterMode, setFilterMode] = useState<FilterMode>("all");
  const [indexingRepoId, setIndexingRepoId] = useState<number | null>(null);
  const [showWebhookGuide, setShowWebhookGuide] = useState(false);
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
    getSession()
      .then((session) => setInstallUrl(session.install_url))
      .catch(() => setInstallUrl(null));
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
        toast.success(`Analysis activated for ${repo.full_name}`, {
          description: "Pull requests on this repository will now trigger automated reviews.",
        });
      } else {
        toast.info(`Analysis disabled for ${repo.full_name}`);
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

  async function handleIndexRepo(repo: RepositoryOut) {
    setIndexingRepoId(repo.id);
    toast.loading(`Indexing ${repo.full_name}...`, { id: `index-${repo.id}` });
    try {
      const res = await fetch("/api/rag/index", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo: repo.full_name }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Indexing failed");
      toast.success(`Vector index created for ${repo.full_name}`, {
        id: `index-${repo.id}`,
        description: `Indexed ${data.chunksIndexed} code chunk(s) in ${data.storageDestination}.`,
      });
    } catch (err) {
      toast.error(`Indexing failed for ${repo.full_name}`, {
        id: `index-${repo.id}`,
        description: err instanceof Error ? err.message : "Error connecting to vector store",
      });
    } finally {
      setIndexingRepoId(null);
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
    <div className="flex flex-col gap-6">
      {/* Header and Quota Indicator */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Repositories</h1>
          <p className="text-muted-foreground text-sm">
            Manage repositories and configure automated pull request webhook reviews.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Badge variant="outline" className="font-mono text-xs py-1 px-2.5 gap-1.5 border-border/80">
            <Radio className="h-3 w-3 text-emerald-400 animate-pulse" />
            <span>
              {activeCount} / 5 Active
            </span>
            <span className="text-muted-foreground text-[10px]">(Free Tier)</span>
          </Badge>

          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowWebhookGuide(!showWebhookGuide)}
            className="text-xs gap-1.5"
          >
            <Webhook className="h-3.5 w-3.5" />
            Webhook Info
          </Button>

          {installUrl && (
            <Button size="sm" nativeButton={false} render={<a href={installUrl} target="_blank" rel="noreferrer" className="text-xs gap-1.5 flex items-center"><span>Add Repository</span><ExternalLink className="h-3 w-3" /></a>} />
          )}
        </div>
      </div>

      {/* Webhook Guidance Card (collapsible) */}
      {showWebhookGuide && (
        <Card className="border-border/80 bg-muted/30 backdrop-blur-sm">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Webhook className="h-4 w-4 text-primary" />
              <span>Real-time Pull Request Webhook Integration</span>
            </CardTitle>
            <CardDescription className="text-xs">
              When analysis is enabled on a repository, GitHub delivers pull request events directly
              to CodeSheriff.
            </CardDescription>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground flex flex-col gap-2">
            <p>
              • <strong>Production URL:</strong> Events are verified with HMAC-SHA256 signatures via{" "}
              <code className="font-mono text-[11px] bg-background px-1.5 py-0.5 rounded border border-border">
                /webhooks/github
              </code>
            </p>
            <p>
              • <strong>Local Development (ngrok):</strong> Forward webhooks to your local machine using{" "}
              <code className="font-mono text-[11px] bg-background px-1.5 py-0.5 rounded border border-border">
                ngrok http 8000
              </code>{" "}
              and update your GitHub App webhook URL with the generated forwarding domain.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Search and Filters Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="relative w-full sm:w-80">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search repositories..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 text-sm rounded-lg border border-border bg-card/60 placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>

        <div className="flex items-center gap-1.5 w-full sm:w-auto overflow-x-auto pb-1 sm:pb-0">
          <Button
            variant={filterMode === "all" ? "secondary" : "ghost"}
            size="sm"
            onClick={() => setFilterMode("all")}
            className="text-xs h-8"
          >
            All ({items.length})
          </Button>
          <Button
            variant={filterMode === "active" ? "secondary" : "ghost"}
            size="sm"
            onClick={() => setFilterMode("active")}
            className="text-xs h-8 gap-1.5"
          >
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
            Active ({activeCount})
          </Button>
          <Button
            variant={filterMode === "private" ? "secondary" : "ghost"}
            size="sm"
            onClick={() => setFilterMode("private")}
            className="text-xs h-8 gap-1.5"
          >
            <Lock className="h-3 w-3" />
            Private
          </Button>
          <Button
            variant={filterMode === "public" ? "secondary" : "ghost"}
            size="sm"
            onClick={() => setFilterMode("public")}
            className="text-xs h-8 gap-1.5"
          >
            <Globe className="h-3 w-3" />
            Public
          </Button>
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
          <AlertTitle>No repositories found</AlertTitle>
          <AlertDescription className="flex flex-col items-start gap-3">
            <span>
              This account has no installation of the App, or the installation grants access to no
              repositories.
            </span>
            {installUrl && (
              <Button size="sm" nativeButton={false} render={<a href={installUrl}>Install on a repository</a>} />
            )}
          </AlertDescription>
        </Alert>
      )}

      {/* Repositories Table */}
      {filteredItems.length > 0 && (
        <div className="rounded-lg border border-border/80 overflow-hidden bg-card/50">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Repository</TableHead>
                <TableHead>Default Branch</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Automated Analysis</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredItems.map((repo) => (
                <TableRow key={repo.id}>
                  <TableCell className="font-medium">
                    <div className="flex items-center gap-2">
                      <FolderGit2 className="h-4 w-4 text-muted-foreground shrink-0" />
                      <span>{repo.full_name}</span>
                      {repo.is_private ? (
                        <Badge variant="secondary" className="text-[10px] gap-1 py-0 px-1.5">
                          <Lock className="h-2.5 w-2.5" />
                          private
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-[10px] gap-1 py-0 px-1.5 text-muted-foreground">
                          <Globe className="h-2.5 w-2.5" />
                          public
                        </Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-muted-foreground font-mono text-xs">
                    {repo.default_branch}
                  </TableCell>
                  <TableCell>
                    {repo.analysis_enabled ? (
                      <Badge variant="outline" className="text-[10px] font-mono text-emerald-400 border-emerald-500/30 bg-emerald-500/10">
                        ● Connected
                      </Badge>
                    ) : (
                      <Badge variant="secondary" className="text-[10px] font-mono text-muted-foreground">
                        Idle
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-3">
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={indexingRepoId === repo.id}
                        onClick={() => handleIndexRepo(repo)}
                        className="h-7 px-2 text-[11px] gap-1 text-muted-foreground hover:text-foreground"
                        title="Generate vector embeddings for codebase RAG"
                      >
                        <Database className="h-3 w-3" />
                        <span>{indexingRepoId === repo.id ? "Indexing..." : "Index RAG"}</span>
                      </Button>

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
