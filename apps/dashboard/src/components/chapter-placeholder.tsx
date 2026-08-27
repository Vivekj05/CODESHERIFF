import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * A page that does not exist yet, saying so.
 *
 * Chapter 4 builds the shell and nothing else — every route below renders against mock data with no
 * backend. A placeholder that names the chapter that fills it is more useful than a blank page and,
 * more importantly, cannot be mistaken for a working feature during a demo.
 */
export function ChapterPlaceholder({
  chapter,
  title,
  children,
}: {
  chapter: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <Card className="border-dashed">
      <CardHeader>
        <CardDescription className="font-mono text-xs uppercase tracking-wide">
          {chapter}
        </CardDescription>
        <CardTitle className="text-base">{title}</CardTitle>
      </CardHeader>
      <CardContent className="text-muted-foreground text-sm">{children}</CardContent>
    </Card>
  );
}
