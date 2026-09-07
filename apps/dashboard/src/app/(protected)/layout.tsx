import { AppShell } from "@/components/app-shell";

/**
 * Every signed-in route renders inside the shell.
 *
 * Chapter 4's placeholder session is gone (D-033): the shell now reads a real session from the API,
 * and sends anyone without one to `/sign-in`. That redirect is a rendering decision, not a security
 * control — the API re-checks the session cookie on every request and returns 401 regardless of
 * what this layout chose to draw.
 */
export default function ProtectedLayout({ children }: { children: React.ReactNode }) {
  return <AppShell>{children}</AppShell>;
}
