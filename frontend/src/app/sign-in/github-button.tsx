"use client";

import { ArrowUpRight } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { buttonVariants } from "@/components/chai/button";
import { GitHubMark } from "@/components/github-mark";
import { signInWithGitHub } from "@/lib/auth-client";
import { cn } from "@/lib/utils";

/**
 * Starts Better Auth's GitHub flow. The page decides where it returns to, and whether it starts by
 * itself (after an App install, to refresh the installation list).
 */
export function GitHubButton({
  callbackURL,
  autoStart = false,
}: {
  callbackURL: string;
  autoStart?: boolean;
}) {
  const [pending, setPending] = useState(autoStart);
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  async function start() {
    setPending(true);
    setError(null);
    const result = await signInWithGitHub(callbackURL);
    // On success the browser is already navigating to GitHub; only a failure comes back here.
    if (result?.error) {
      setError(result.error.message ?? "GitHub sign-in could not start.");
      setPending(false);
    }
  }

  useEffect(() => {
    // Once, even under React's development double-invoke.
    if (!autoStart || started.current) return;
    started.current = true;
    void start();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoStart]);

  return (
    <div className="flex w-full flex-col gap-2">
      <button
        type="button"
        onClick={() => void start()}
        disabled={pending}
        className={cn(buttonVariants({ variant: "solid", size: "lg" }), "w-full")}
      >
        <GitHubMark />
        {pending ? "Opening GitHub" : "Continue with GitHub"}
        <ArrowUpRight className="-ml-1" aria-hidden="true" />
      </button>
      {error && (
        <p role="alert" className="text-sm text-red-700 dark:text-red-400">
          {error}
        </p>
      )}
    </div>
  );
}
