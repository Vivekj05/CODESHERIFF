"use client";

import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { FolderGit2, Gauge, LayoutDashboard, ListChecks, LogOut, Settings, User } from "lucide-react";

import { BrandLogo } from "@/components/brand-logo";
import { ThemeSwitcher } from "@/components/theme-switcher";
import type { SessionInfo } from "@/lib/api";
import { cn } from "@/lib/utils";

export const NAV_ITEMS = [
  { href: "/overview", label: "Overview", icon: LayoutDashboard },
  { href: "/repositories", label: "Repositories", icon: FolderGit2 },
  { href: "/audits", label: "Audits", icon: ListChecks },
  { href: "/calibration", label: "Calibration", icon: Gauge },
  { href: "/settings", label: "Settings", icon: Settings },
] as const;

export function isActive(pathname: string, href: string): boolean {
  return pathname === href || pathname.startsWith(`${href}/`);
}

/** The links alone, shared by the desktop sidebar and the phone menu. */
export function NavLinks({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();
  return (
    <nav className="flex flex-col gap-0.5" aria-label="Dashboard">
      {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
        const active = isActive(pathname, href);
        return (
          <Link
            key={href}
            href={href}
            onClick={onNavigate}
            aria-current={active ? "page" : undefined}
            className={cn(
              "flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors duration-200 outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
              active
                ? "bg-accent/60 text-foreground"
                : "text-muted-foreground hover:bg-accent/40 hover:text-foreground",
            )}
          >
            <Icon className="size-4 shrink-0" aria-hidden="true" />
            {label}
          </Link>
        );
      })}
    </nav>
  );
}

export function SessionCard({ session, onSignOut }: { session: SessionInfo; onSignOut: () => void }) {
  return (
    <div className="flex items-center justify-between gap-2 rounded-xl border border-card-edge p-2.5">
      <div className="flex min-w-0 items-center gap-2.5">
        {session.avatar_url ? (
          <Image
            src={session.avatar_url}
            alt=""
            width={32}
            height={32}
            className="size-8 shrink-0 rounded-full border border-card-edge"
            unoptimized
          />
        ) : (
          <span className="flex size-8 shrink-0 items-center justify-center rounded-full border border-card-edge text-muted-foreground">
            <User className="size-4" aria-hidden="true" />
          </span>
        )}
        <div className="flex min-w-0 flex-col">
          <span className="truncate text-sm font-medium">{session.name || session.login}</span>
          <span className="truncate text-xs text-muted-foreground">
            {session.installation_count} installation{session.installation_count === 1 ? "" : "s"}
          </span>
        </div>
      </div>
      <button
        type="button"
        onClick={onSignOut}
        aria-label="Sign out"
        title="Sign out"
        className="inline-flex size-8 shrink-0 cursor-pointer items-center justify-center rounded-md text-muted-foreground transition-colors duration-200 outline-none hover:text-brand focus-visible:ring-[3px] focus-visible:ring-ring/50"
      >
        <LogOut className="size-4" aria-hidden="true" />
      </button>
    </div>
  );
}

/** The desktop sidebar: the mark, the sections, and who is signed in. */
export function AppSidebar({
  session,
  onSignOut,
}: {
  session: SessionInfo | null;
  onSignOut: () => void;
}) {
  return (
    <div className="flex h-full flex-col justify-between gap-6 p-4">
      <div className="flex flex-col gap-6">
        <div className="flex items-center justify-between px-1">
          <Link href="/overview" aria-label="CodeSheriff dashboard">
            <BrandLogo />
          </Link>
          <ThemeSwitcher />
        </div>
        <NavLinks />
      </div>
      {session && <SessionCard session={session} onSignOut={onSignOut} />}
    </div>
  );
}
