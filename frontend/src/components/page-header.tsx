import { cn } from "@/lib/utils";

/**
 * The head of every dashboard page: a ChaiUI page title, a lead with at most one highlighted
 * phrase, and an optional action on the right.
 *
 * Left-aligned rather than centred, unlike a ChaiUI listing page: next to a sidebar, a centred
 * title floats away from the content it labels.
 */
export function PageHeader({
  title,
  children,
  action,
  className,
}: {
  title: React.ReactNode;
  children?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between", className)}>
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-medium sm:text-3xl">{title}</h1>
        {children && (
          <p className="max-w-3xl text-base text-neutral-700 dark:text-neutral-400">{children}</p>
        )}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}
