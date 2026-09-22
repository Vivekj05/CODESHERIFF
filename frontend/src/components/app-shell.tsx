"use client";

import { useRouter } from "next/navigation";

import { AppSidebar } from "@/components/app-sidebar";
import { SessionSkeleton, useSession } from "@/components/session-gate";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { logout } from "@/lib/api";

/**
 * The signed-in shell: navigation, who you are, and a way out.
 */
export function AppShell({ children }: { children: React.ReactNode }) {
  const state = useSession();
  const router = useRouter();

  async function signOut() {
    try {
      await logout();
    } finally {
      router.replace("/sign-in");
    }
  }

  return (
    <div className="flex min-h-full flex-1">
      <aside className="hidden w-64 shrink-0 border-r border-border/70 bg-card/40 backdrop-blur-md md:block">
        <AppSidebar
          session={state.status === "signed-in" ? state.session : null}
          onSignOut={signOut}
        />
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between gap-4 border-b px-6 py-3">
          <span className="text-muted-foreground text-sm">
            {state.status === "signed-in"
              ? `${state.session.name ?? state.session.login} · ${state.session.installation_count} installation${state.session.installation_count === 1 ? "" : "s"}`
              : ""}
          </span>
          {state.status === "signed-in" && (
            <Button variant="ghost" size="sm" onClick={signOut}>
              Sign out
            </Button>
          )}
        </header>

        <main className="min-w-0 flex-1 p-6">
          {state.status === "loading" && <SessionSkeleton />}
          {state.status === "signed-out" && (
            <p className="text-muted-foreground text-sm">Redirecting to sign in…</p>
          )}
          {state.status === "unconfigured" && (
            <Alert variant="destructive">
              <AlertTitle>The API cannot serve a session</AlertTitle>
              <AlertDescription>
                {state.detail} See <code>.env.example</code> and PLAN.md Chapter 5 for the GitHub
                App registration steps.
              </AlertDescription>
            </Alert>
          )}
          {state.status === "signed-in" && children}
        </main>
      </div>
    </div>
  );
}
