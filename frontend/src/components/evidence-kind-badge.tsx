import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { EvidenceKind } from "@/lib/types";
import { cn } from "@/lib/utils";

/**
 * Three kinds, never two.
 *
 * SILENCE means an agent ran to completion and found nothing — evidence that can push a posterior
 * down, but only for the CWEs it can actually detect. ABSTENTION means it could not run at all, and
 * contributes nothing. Collapsing them into one "no finding" chip in the UI would repeat, on
 * screen, the exact bug the contract was rewritten to fix (D-005).
 */
const COPY: Record<EvidenceKind, { label: string; explanation: string; className: string }> = {
  detection: {
    label: "detection",
    explanation: "Ran, and found something. Carries a finding key and an in-scope CWE.",
    className: "border-red-500/40 text-red-700 dark:text-red-400",
  },
  silence: {
    label: "silence",
    explanation:
      "Ran to completion and found nothing. Counts against the CWEs this agent can actually detect, and no others.",
    className: "border-emerald-500/40 text-emerald-700 dark:text-emerald-400",
  },
  abstention: {
    label: "abstention",
    explanation:
      "Could not run, or could not run soundly. Contributes nothing to the posterior — an agent that could not look does not get to vote the code innocent.",
    className: "border-neutral-400/50 text-muted-foreground",
  },
};

export function EvidenceKindBadge({ kind }: { kind: EvidenceKind }) {
  const { label, explanation, className } = COPY[kind];
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Badge variant="outline" className={cn("cursor-help", className)}>
            {label}
          </Badge>
        }
      />
      <TooltipContent className="max-w-xs">{explanation}</TooltipContent>
    </Tooltip>
  );
}
