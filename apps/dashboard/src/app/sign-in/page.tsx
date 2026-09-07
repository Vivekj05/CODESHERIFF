import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { API_BASE_URL } from "@/lib/api";

/**
 * Sign-in is a plain link, not a fetch.
 *
 * The OAuth flow is a sequence of top-level browser navigations — this page → the API → GitHub →
 * the API → back here. Starting it with `fetch` would put the redirect inside XHR, where the
 * browser cannot show GitHub's consent screen and cannot set the state cookie for the return trip.
 *
 * Outside the `(protected)` group on purpose: it is the one page that must render for someone with
 * no session.
 */
export default function SignInPage() {
  return (
    <div className="flex min-h-full flex-1 items-center justify-center p-6">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>CodeSheriff</CardTitle>
          <CardDescription>
            Security review for pull requests, with confidence you can check.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <p className="text-muted-foreground text-sm">
            Sign in with GitHub to see the repositories this App is installed on. CodeSheriff reads
            pull request contents and writes review comments; it never pushes code.
          </p>
          <Button
            render={
              <a href={`${API_BASE_URL}/auth/login?next=%2Frepositories`}>Sign in with GitHub</a>
            }
          />
          <p className="text-muted-foreground text-xs">
            Signing in grants no access by itself. What you can see is derived from GitHub each time
            you sign in, from the installations your account already reaches.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
