"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { Skeleton } from "@/components/ui/skeleton";
import { ApiError, getSession, type SessionInfo } from "@/lib/api";

/**
 * Reads the session from the API and renders the shell around it.
 *
 * `getSession()` asks the API, with the Better Auth token attached (D-101). That one call both
 * proves the token verifies and lets the API record any installation it has not seen yet, so the
 * pages that follow can list their repositories.
 *
 * This is not a security boundary: it decides what to *render*. Every answer that matters comes
 * from the API, which verifies the token on every request and does not care what the UI believes.
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
          // Back to where they were going, once signed in.
          router.replace(`/sign-in?next=${encodeURIComponent(window.location.pathname)}`);
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
