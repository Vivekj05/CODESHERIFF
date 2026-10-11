"use client";

import { createAuthClient } from "better-auth/react";
import { jwtClient } from "better-auth/client/plugins";

/**
 * The browser side of Better Auth. Same origin as the dashboard, so no base URL is needed.
 *
 * `token()` returns the short-lived JWT the Python API accepts; `lib/api.ts` caches it until shortly
 * before it expires.
 */
export const authClient = createAuthClient({
  plugins: [jwtClient()],
});

export function signInWithGitHub(callbackURL = "/overview") {
  return authClient.signIn.social({ provider: "github", callbackURL });
}
