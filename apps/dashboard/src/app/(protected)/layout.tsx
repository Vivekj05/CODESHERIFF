import { SidebarNav } from "@/components/sidebar-nav";
import { Badge } from "@/components/ui/badge";
import { getPlaceholderSession } from "@/lib/session";

/**
 * The application shell for every signed-in route.
 *
 * ⚠️ **This layout protects nothing yet.** `getPlaceholderSession()` cannot fail, so there is no
 * branch here that denies anyone — the route group is structure, not a security boundary.
 * Authentication is Chapter 5: OAuth, session handling, App installation and per-repo permission
 * derivation. When it lands, this layout gains the `if (!session) redirect("/sign-in")` that the
 * name currently implies, and the placeholder banner below disappears with it.
 */
export default function ProtectedLayout({ children }: { children: React.ReactNode }) {
  const session = getPlaceholderSession();

  return (
    <div className="flex min-h-full flex-1">
      <aside className="hidden w-56 shrink-0 border-r p-4 md:block">
        <SidebarNav />
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between gap-4 border-b px-6 py-3">
          <Badge
            variant="outline"
            className="border-amber-500/40 text-amber-700 dark:text-amber-400"
          >
            mock data · no backend · not signed in
          </Badge>
          <span className="text-muted-foreground text-sm">{session.name}</span>
        </header>
        <main className="min-w-0 flex-1 p-6">{children}</main>
      </div>
    </div>
  );
}
