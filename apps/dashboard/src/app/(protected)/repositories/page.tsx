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
import { mockRepositories } from "@/lib/mock-data";

export default function RepositoriesPage() {
  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Repositories</h1>
        <p className="text-muted-foreground text-sm">
          Repositories the GitHub App is installed on.
        </p>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Repository</TableHead>
            <TableHead>Default branch</TableHead>
            <TableHead>Analysis</TableHead>
            <TableHead className="text-right">Open alerts</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {mockRepositories.map((repo) => (
            <TableRow key={repo.id}>
              <TableCell className="font-medium">
                <Link href="/audits" className="hover:underline">
                  {repo.fullName}
                </Link>
                {repo.isPrivate && (
                  <Badge variant="secondary" className="ml-2 text-xs">
                    private
                  </Badge>
                )}
              </TableCell>
              <TableCell className="text-muted-foreground font-mono text-xs">
                {repo.defaultBranch}
              </TableCell>
              <TableCell>
                <Badge variant={repo.analysisEnabled ? "default" : "outline"}>
                  {repo.analysisEnabled ? "enabled" : "disabled"}
                </Badge>
              </TableCell>
              <TableCell className="text-right font-mono tabular-nums">
                {repo.openAlerts}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <ChapterPlaceholder chapter="Chapter 5" title="Connecting real repositories">
        Installing the GitHub App, deriving per-repository permissions, connect and disconnect, and
        infinite scrolling over the installation&apos;s repositories. The rows above are fixtures
        from <code className="font-mono text-xs">lib/mock-data.ts</code>.
      </ChapterPlaceholder>
    </div>
  );
}
