import { ShieldCheck } from "lucide-react";

import { cn } from "@/lib/utils";

/**
 * CodeSheriff's own mark: a shield and the wordmark in Onest.
 *
 * ChaiUI ships a `Logo`, but it is ChaiCode's brand (the cup and "chaicode"), so it is not used
 * here. This follows the same rules: the mark is the one place a warm accent may appear, and it
 * renders no link, so the caller wraps it with an aria-label.
 */
export function BrandLogo({ className, wordmark = true }: { className?: string; wordmark?: boolean }) {
  return (
    <span className={cn("inline-flex items-center gap-2", className)}>
      <span className="flex size-8 items-center justify-center rounded-lg border border-card-edge">
        <ShieldCheck className="size-4.5 text-brand" aria-hidden="true" />
      </span>
      {wordmark && (
        <span className="font-onest text-xl font-medium tracking-tight text-foreground">
          codesheriff
        </span>
      )}
    </span>
  );
}
