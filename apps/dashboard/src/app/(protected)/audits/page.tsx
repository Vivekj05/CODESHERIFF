"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { listAudits, type AuditSummary } from "@/lib/api";

/**
 * Audit history — real rows, replacing Chapter 4's fixtures.
 *
 * Paged by the opaque cursor the API issues rather than by page number. The cursor keys on
 * `(created_at, id)`, so an audit opened by a push mid-scroll cannot make a page skip or repeat,
 * and a tie on the timestamp — two audits from one push — cannot drop one of them.
 *
 * A **superseded** audit is shown as its own state, not as a failure. It is what a developer
 * pushing again looks like, and marking the most ordinary thing anyone does as an error would
 * make the error rate unreadable (D-039).
 */
const STATUS_VARIANT: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  queued: "outline",
  running: "secondary",
  succeeded: "default",
  failed: "destructive",
  superseded: "outline",
};

export default function AuditsPage() {
  const [items, setItems] = useState<AuditSummary[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [exhausted, setExhausted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadedOnce, setLoadedOnce] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const sentinel = useRef<HTMLDivElement | null>(null);

  const loadMore = useCallback(async (fromCursor: string | null) => {
    setLoading(true);
    setError(null);
    try {
      const page = await listAudits(fromCursor);
      setItems((current) => {
        const seen = new Set(current.map((audit) => audit.id));
        return [...current, ...page.items.filter((audit) => !seen.has(audit.id))];
      });
      setCursor(page.next_cursor);
      setExhausted(page.next_cursor === null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not load audits.");
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

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Audits</h1>
        <p className="text-muted-foreground text-sm">
          One audit per pull request head commit. A push abandons the run for the previous head
          rather than failing it.
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
          <AlertTitle>No audits yet</AlertTitle>
          <AlertDescription>
            An audit is opened when a pull request is opened or updated on a repository with
            analysis switched on.
          </AlertDescription>
        </Alert>
      )}

      {items.length > 0 && (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Pull request</TableHead>
              <TableHead>Repository</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Units</TableHead>
              <TableHead className="text-right">Findings</TableHead>
              <TableHead className="text-right">Alerts</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((audit) => (
              <TableRow key={audit.id}>
                <TableCell className="font-medium">
                  <Link href={`/audits/${audit.id}`} className="hover:underline">
                    #{audit.pr_number}
                  </Link>
                  <span className="text-muted-foreground ml-2 font-mono text-xs">
                    {audit.head_sha.slice(0, 7)}
                  </span>
                </TableCell>
                <TableCell className="text-muted-foreground text-sm">
                  {audit.repository_full_name}
                </TableCell>
                <TableCell>
                  <Badge variant={STATUS_VARIANT[audit.status] ?? "outline"}>{audit.status}</Badge>
                </TableCell>
                <TableCell className="text-right font-mono tabular-nums">{audit.units}</TableCell>
                <TableCell className="text-right font-mono tabular-nums">
                  {audit.findings}
                </TableCell>
                <TableCell className="text-right font-mono tabular-nums">
                  {audit.alerts > 0 ? (
                    <span className="text-destructive font-semibold">{audit.alerts}</span>
                  ) : (
                    audit.alerts
                  )}
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
