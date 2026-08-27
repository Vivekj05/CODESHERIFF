"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { Skeleton } from "@/components/ui/skeleton";
import { ApiError, getSession, type SessionInfo } from "@/lib/api";

/**
 * Reads the session from the API and renders the shell around it.
 *
 * Client-side rather than in a server component, deliberately. The session cookie belongs to the
 * API's origin. In development that happens to be the same host as the dashboard — cookies ignore
 * ports — so a server component could read and forward it, and would then break the day the API
 * moves to its own subdomain. Fetching from the browser behaves the same in both.
 *
 * This is not a security boundary either: it decides what to *render*. Every answer that matters
 * comes from the API, which re-checks the cookie on every request and does not care what the UI
 * believes.
 */
export type SessionState =
  | { status: "loading" }
  | { status: "signed-in"; session: SessionInfo }
  | { status: "signed-out" }
  | { status: "unconfigured"; detail: string };

export function useSession(): SessionState {
  const [state, setState] = useState<SessionState>({ status: "loading" });
  const router = useRouter();

  useEffect(() => {
    let cancelled = false;

    getSession()
      .then((session) => {
        if (!cancelled) setState({ status: "signed-in", session });
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        if (error instanceof ApiError && error.status === 401) {
          setState({ status: "signed-out" });
          router.replace("/sign-in");
          return;
        }
        // 501 means the deployment has no GitHub App configured. Telling the user to sign in again
        // would be a lie they could follow forever.
        const detail =
          error instanceof ApiError
            ? error.message
            : "The API is not reachable. Is it running on the configured origin?";
        setState({ status: "unconfigured", detail });
      });

    return () => {
      cancelled = true;
    };
  }, [router]);

  return state;
}

export function SessionSkeleton() {
  return (
    <div className="flex flex-col gap-3 p-6">
      <Skeleton className="h-6 w-48" />
      <Skeleton className="h-4 w-72" />
      <Skeleton className="h-32 w-full" />
    </div>
  );
}
