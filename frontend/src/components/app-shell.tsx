"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { AppSidebar, NavLinks, SessionCard } from "@/components/app-sidebar";
import { Backdrop } from "@/components/backdrop";
import { BrandLogo } from "@/components/brand-logo";
import { MenuToggle } from "@/components/menu-toggle";
import { SessionSkeleton, useSession } from "@/components/session-gate";
import { ThemeSwitcher } from "@/components/theme-switcher";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { logout } from "@/lib/api";

/**
 * The signed-in shell. A sidebar from md up; below that, a sticky bar whose menu button opens the
 * same links. Signing out, or arriving without a session, goes back to the home page, which is
 * where sign-in starts.
 */
export function AppShell({ children }: { children: React.ReactNode }) {
  const state = useSession();
  const router = useRouter();
  const [menuOpen, setMenuOpen] = useState(false);
  const session = state.status === "signed-in" ? state.session : null;

  async function signOut() {
    try {
      await logout();
    } finally {
      router.replace("/");
    }
  }

  return (
    <div className="relative isolate flex min-h-full flex-1 overflow-clip">
      <Backdrop className="opacity-60" />

      <aside className="sticky top-0 hidden h-dvh w-64 shrink-0 border-r border-card-edge md:block">
        <AppSidebar session={session} onSignOut={signOut} />
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-40 border-b border-card-edge bg-background/60 backdrop-blur-md md:hidden">
          <div className="flex items-center justify-between px-6 py-3">
            <Link href="/overview" aria-label="CodeSheriff dashboard">
              <BrandLogo />
            </Link>
            <div className="flex items-center gap-1">
              <ThemeSwitcher />
              <MenuToggle open={menuOpen} onClick={() => setMenuOpen((v) => !v)} />
            </div>
          </div>
          {menuOpen && (
            <div className="flex flex-col gap-4 border-t border-card-edge px-6 py-4">
              <NavLinks onNavigate={() => setMenuOpen(false)} />
              {session && <SessionCard session={session} onSignOut={signOut} />}
            </div>
          )}
        </header>

        <main className="mx-auto w-full max-w-6xl min-w-0 flex-1 p-6 sm:p-12">
          {state.status === "loading" && <SessionSkeleton />}
          {state.status === "signed-out" && (
            <p className="text-sm text-muted-foreground">Taking you to the home page to sign in.</p>
          )}
          {state.status === "unconfigured" && (
            <Alert variant="destructive">
              <AlertTitle>The API cannot serve a session</AlertTitle>
              <AlertDescription>
                {state.detail} See <code>.env.example</code> and{" "}
                <code>docs/github-app-setup.md</code> for the GitHub App registration steps.
              </AlertDescription>
            </Alert>
          )}
          {state.status === "signed-in" && children}
        </main>
      </div>
    </div>
  );
}
