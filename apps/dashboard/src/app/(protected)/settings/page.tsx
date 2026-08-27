import { ChapterPlaceholder } from "@/components/chapter-placeholder";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { IN_SCOPE_CWES } from "@/lib/types";
import { Badge } from "@/components/ui/badge";

export default function SettingsPage() {
  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-muted-foreground text-sm">Per-repository analysis configuration.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">CWE scope</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div className="flex flex-wrap gap-2">
            {IN_SCOPE_CWES.map((cwe) => (
              <Badge key={cwe} variant="secondary" className="font-mono text-xs">
                {cwe}
              </Badge>
            ))}
          </div>
          <p className="text-muted-foreground text-sm">
            A closed set. Widening it invalidates every number fitted against it, so it changes by
            an explicit decision in the backend contract — not from this page.
          </p>
        </CardContent>
      </Card>

      <ChapterPlaceholder chapter="Chapter 15" title="Editable settings">
        Alert threshold, enabled agents and per-repository CWE scope, written through the API. The
        threshold in particular is selected on the validation split, never chosen here to make a
        dashboard look tidier.
      </ChapterPlaceholder>
    </div>
  );
}
