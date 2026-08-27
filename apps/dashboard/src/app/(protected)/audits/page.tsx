import Link from "next/link";

import { ChapterPlaceholder } from "@/components/chapter-placeholder";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { mockAudits } from "@/lib/mock-data";
import type { AuditStatus } from "@/lib/types";

const STATUS_VARIANT: Record<AuditStatus, "default" | "secondary" | "outline" | "destructive"> = {
  queued: "outline",
  running: "secondary",
  succeeded: "default",
  failed: "destructive",
};

export default function AuditsPage() {
  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Audits</h1>
        <p className="text-muted-foreground text-sm">
          One audit per pull request head commit.
        </p>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Pull request</TableHead>
            <TableHead>Repository</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Units</TableHead>
            <TableHead className="text-right">Findings</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {mockAudits.map((audit) => (
            <TableRow key={audit.id}>
              <TableCell className="font-medium">
                <Link href={`/audits/${audit.id}`} className="hover:underline">
                  #{audit.prNumber} {audit.prTitle}
                </Link>
              </TableCell>
              <TableCell className="text-muted-foreground text-sm">
                {audit.repositoryFullName}
              </TableCell>
              <TableCell>
                <Badge variant={STATUS_VARIANT[audit.status]}>{audit.status}</Badge>
              </TableCell>
              <TableCell className="text-right font-mono tabular-nums">
                {audit.unitsAnalysed}
              </TableCell>
              <TableCell className="text-right font-mono tabular-nums">
                {audit.findings.length}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <ChapterPlaceholder chapter="Chapter 15" title="Real audit history">
        Audits arrive from the FastAPI read endpoints, with stats, verdict summaries and charts.
        Until Chapter 6 puts the webhook and the queue in place there is nothing to record, and
        until Chapter 14 fits a calibration artifact every posterior stays provisional.
      </ChapterPlaceholder>
    </div>
  );
}
