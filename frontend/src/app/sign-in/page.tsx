import { headers } from "next/headers";
import Link from "next/link";
import { redirect } from "next/navigation";

import { Backdrop } from "@/components/backdrop";
import { BrandLogo } from "@/components/brand-logo";
import { auth } from "@/lib/auth";

import { GitHubButton } from "./github-button";

/**
 * The sign-in page: one card, one action (D-101).
 *
 * Home's "Sign in" buttons land here, and so does anyone who reaches a dashboard page without a
 * session, with `next` naming where they were going. `next` is reduced to a same-origin path
 * before it is used: a redirect target taken from a query string is an open redirect otherwise,
 * and `//evil.example` is the form that passes a naive `startsWith("/")`.
 *
 * Someone already signed in skips the card.
 */
function safeNext(candidate: string | string[] | undefined): string {
  const value = Array.isArray(candidate) ? candidate[0] : candidate;
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) {
    return "/overview";
  }
  return value;
}

export default async function SignInPage({ searchParams }: PageProps<"/sign-in">) {
  const next = safeNext((await searchParams).next);

  const session = await auth.api.getSession({ headers: await headers() });
  if (session) redirect(next);

  return (
    <div className="relative isolate flex min-h-full flex-1 flex-col overflow-clip">
      <Backdrop />
      <header className="px-6 py-5 sm:px-12">
        <Link href="/" aria-label="CodeSheriff home" className="w-fit">
          <BrandLogo />
        </Link>
      </header>

      <main className="flex flex-1 items-center justify-center p-6">
        <section
          aria-labelledby="sign-in-h"
          className="card-chai flex w-full max-w-sm flex-col items-center gap-6 p-8 text-center"
        >
          <BrandLogo wordmark={false} className="scale-125" />
          <div className="flex flex-col gap-2">
            <h1 id="sign-in-h" className="text-2xl font-medium">
              Welcome back
            </h1>
            <p className="text-sm text-muted-foreground">
              Sign in with GitHub to see the audits CodeSheriff has run on your pull requests.
            </p>
          </div>

          <GitHubButton callbackURL={next} />

          <p className="text-xs leading-relaxed text-muted-foreground">
            Signing in reads your GitHub profile, email and which installations of the CodeSheriff
            App you can reach. You can revoke it at any time in your GitHub settings, under
            Applications.
          </p>
        </section>
      </main>
    </div>
  );
}
