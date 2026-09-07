import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/**
 * One number with its label, and room for the caveat underneath.
 *
 * The `note` slot is not decoration. Every count on the overview needs a qualifier to be read
 * correctly — "across repositories you can see", "of which one alerted" — and a tile that had
 * nowhere to put one would silently drop it.
 */
export function Stat({
  label,
  value,
  note,
  emphasis = false,
}: {
  label: string;
  value: string | number;
  note?: string;
  emphasis?: boolean;
}) {
  return (
    <Card>
      <CardContent className="flex flex-col gap-1 py-4">
        <span className="text-muted-foreground text-xs uppercase tracking-wide">{label}</span>
        <span
          className={cn(
            "font-mono text-2xl font-semibold tabular-nums",
            emphasis && "text-destructive",
          )}
        >
          {value}
        </span>
        {note && <span className="text-muted-foreground text-xs">{note}</span>}
      </CardContent>
    </Card>
  );
}
