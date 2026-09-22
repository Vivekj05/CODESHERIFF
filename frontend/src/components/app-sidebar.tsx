"use client";

import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  FolderGit2,
  Gauge,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Settings,
  Shield,
  User,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { SessionInfo } from "@/lib/api";

const NAV_ITEMS = [
  { href: "/overview", label: "Overview", icon: LayoutDashboard },
  { href: "/repositories", label: "Repositories", icon: FolderGit2 },
  { href: "/audits", label: "Audits & Reviews", icon: ListChecks },
  { href: "/calibration", label: "Calibration", icon: Gauge },
  { href: "/settings", label: "Settings", icon: Settings },
] as const;

interface AppSidebarProps {
  session?: SessionInfo | null;
  onSignOut?: () => void;
}

export function AppSidebar({ session, onSignOut }: AppSidebarProps) {
  const pathname = usePathname();

  return (
    <div className="flex h-full flex-col justify-between p-4">
      <div className="flex flex-col gap-6">
        {/* Logo and Brand */}
        <div className="flex items-center gap-2.5 px-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/15 border border-primary/30 text-primary">
            <Shield className="h-4 w-4" />
          </div>
          <div className="flex flex-col">
            <span className="font-semibold text-sm tracking-tight leading-none">CodeSheriff</span>
            <span className="text-[10px] text-muted-foreground font-mono mt-0.5">
              Calibrated Review
            </span>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="flex flex-col gap-1" aria-label="Main Navigation">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/70 px-2 mb-1.5">
            Platform
          </div>
          {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
            const active = pathname === href || (href !== "/overview" && pathname.startsWith(`${href}/`));
            return (
              <Link
                key={href}
                href={href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-all duration-150",
                  active
                    ? "bg-primary text-primary-foreground font-medium shadow-sm"
                    : "text-muted-foreground hover:bg-accent/60 hover:text-foreground",
                )}
              >
                <Icon className="h-4 w-4 shrink-0" aria-hidden />
                <span>{label}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      {/* User Session Footer */}
      {session && (
        <div className="border-t border-border/60 pt-4 flex flex-col gap-3">
          <div className="flex items-center justify-between px-2">
            <div className="flex items-center gap-2.5 min-w-0">
              {session.avatar_url ? (
                <Image
                  src={session.avatar_url}
                  alt={session.login}
                  width={32}
                  height={32}
                  className="h-8 w-8 rounded-full border border-border shrink-0"
                  unoptimized
                />
              ) : (
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-muted border border-border shrink-0 text-muted-foreground">
                  <User className="h-4 w-4" />
                </div>
              )}
              <div className="min-w-0 flex flex-col">
                <span className="text-xs font-medium truncate text-foreground">
                  {session.name || session.login}
                </span>
                <span className="text-[10px] text-muted-foreground font-mono truncate">
                  @{session.login}
                </span>
              </div>
            </div>
            {onSignOut && (
              <Button
                variant="ghost"
                size="icon"
                onClick={onSignOut}
                className="h-8 w-8 text-muted-foreground hover:text-foreground shrink-0"
                title="Sign out"
              >
                <LogOut className="h-4 w-4" />
              </Button>
            )}
          </div>

          <div className="rounded-lg bg-muted/40 border border-border/40 p-2.5 text-[11px] text-muted-foreground flex items-center justify-between">
            <span>Installations</span>
            <Badge variant="secondary" className="font-mono text-[10px] py-0 px-1.5">
              {session.installation_count} active
            </Badge>
          </div>
        </div>
      )}
    </div>
  );
}
