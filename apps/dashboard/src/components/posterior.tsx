import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { Calibration } from "@/lib/types";
import { cn } from "@/lib/utils";

/**
 * The only way a probability reaches the screen.
 *
 * The thesis of this project is that a stated 87% must correspond to being right 87% of the time.
 * A bare "87%" is precisely the failure it attacks — every existing PR security tool emits a
 * confident number with no reliability behind it, which is why developers learn to ignore them.
 *
 * So this component refuses to render a number alone. While `calibration.isProvisional` is true —
 * which it will be until Chapter 14 fits likelihood ratios against the calibration split — the
 * number is shown as an estimate from hand-set ratios and says so in the markup, not in a caption
 * somebody can forget to include (D-010). Once a fitted artifact exists, the same component shows
 * the ECE and the sample size the claim rests on.
 *
 * Chapter 15 will make this richer. It must not make it quieter.
 */
export function Posterior({
  value,
  calibration,
  threshold,
  size = "default",
}: {
  value: number;
  calibration: Calibration;
  threshold?: number;
  size?: "default" | "large";
}) {
  const percent = Math.round(value * 100);

  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-baseline gap-2">
        <span
          className={cn(
            "font-mono font-semibold tabular-nums",
            size === "large" ? "text-4xl" : "text-lg",
          )}
        >
          {percent}%
        </span>
        {threshold !== undefined && (
          <span className="text-muted-foreground text-xs">
            alert at {Math.round(threshold * 100)}%
          </span>
        )}
      </div>
      <CalibrationTag calibration={calibration} />
    </div>
  );
}

export function CalibrationTag({ calibration }: { calibration: Calibration }) {
  if (calibration.isProvisional) {
    return (
      <Tooltip>
        <TooltipTrigger
          render={
            <Badge
              variant="outline"
              className="w-fit cursor-help border-amber-500/40 text-amber-700 dark:text-amber-400"
            >
              provisional — not calibrated
            </Badge>
          }
        />
        <TooltipContent className="max-w-xs">
          Produced by hand-set likelihood ratios, not fitted ones. No calibration artifact exists
          yet, so this number carries no measured reliability. Chapter 14 fits the ratios on the
          calibration split and reports ECE and Brier score.
        </TooltipContent>
      </Tooltip>
    );
  }

  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Badge variant="secondary" className="w-fit cursor-help font-mono text-xs">
            ECE {calibration.ece?.toFixed(3) ?? "—"} · n={calibration.nCases ?? "—"}
          </Badge>
        }
      />
      <TooltipContent className="max-w-xs">
        Expected calibration error over {calibration.nCases ?? "—"} labelled cases. Lower is better:
        it measures how far stated confidence drifts from observed accuracy.
      </TooltipContent>
    </Tooltip>
  );
}
