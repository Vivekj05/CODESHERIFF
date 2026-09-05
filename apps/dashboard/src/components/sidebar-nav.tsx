"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { FolderGit2, Gauge, LayoutDashboard, ListChecks, Settings, ShieldAlert } from "lucide-react";

import { cn } from "@/lib/utils";

const LINKS = [
  { href: "/overview", label: "Overview", icon: LayoutDashboard },
  { href: "/repositories", label: "Repositories", icon: FolderGit2 },
  { href: "/audits", label: "Audits", icon: ListChecks },
  // Its own destination rather than a panel inside Settings. The reliability behind a posterior
  // is the product, not a configuration detail, and burying it would repeat the failure this
  // project exists to name.
  { href: "/calibration", label: "Calibration", icon: Gauge },
  { href: "/settings", label: "Settings", icon: Settings },
] as const;

export function SidebarNav() {
  const pathname = usePathname();

  return (
    <nav className="flex flex-col gap-1" aria-label="Main">
      <div className="mb-4 flex items-center gap-2 px-2">
        <ShieldAlert className="size-5" aria-hidden />
        <span className="font-semibold tracking-tight">CodeSheriff</span>
      </div>
      {LINKS.map(({ href, label, icon: Icon }) => {
        const active = pathname === href || pathname.startsWith(`${href}/`);
        return (
          <Link
            key={href}
            href={href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "flex items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors",
              active
                ? "bg-accent text-accent-foreground font-medium"
                : "text-muted-foreground hover:bg-accent/50 hover:text-foreground",
            )}
          >
            <Icon className="size-4" aria-hidden />
            {label}
          </Link>
        );
      })}
    </nav>
  );
}
