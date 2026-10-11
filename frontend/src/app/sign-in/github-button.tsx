"use client";

import { ArrowUpRight } from "lucide-react";
import { useState } from "react";

import { buttonVariants } from "@/components/chai/button";
import { signInWithGitHub } from "@/lib/auth-client";
import { cn } from "@/lib/utils";

/** Starts Better Auth's GitHub flow. The page decides where it returns to. */
export function GitHubButton({ callbackURL }: { callbackURL: string }) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

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

/** GitHub's mark, from Octicons (MIT). Lucide no longer ships brand icons. */
function GitHubMark() {
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" className="size-4 fill-current">
      <path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z" />
    </svg>
  );
}
