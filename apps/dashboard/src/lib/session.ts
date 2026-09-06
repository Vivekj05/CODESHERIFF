/**
 * PLACEHOLDER. This protects nothing.
 *
 * Chapter 4 builds the shell; authentication is Chapter 5 (GitHub OAuth, App installation,
 * per-repo permission derivation). Until then `getSession()` always returns the same fake
 * developer, so the `(protected)` route group renders in development with no backend running —
 * which is the chapter's acceptance criterion.
 *
 * It is named and typed to be impossible to mistake for a security boundary: there is no code path
 * here that can deny anyone. Chapter 5 replaces this file wholesale with a real session read, and
 * the layout that calls it gains an actual redirect.
 */

export interface DevSession {
  login: string;
  name: string;
  /** Always true here. A real session can be absent; this one cannot. */
  isPlaceholder: true;
}

export function getPlaceholderSession(): DevSession {
  return {
    login: "dev",
    name: "Development session",
    isPlaceholder: true,
  };
}
