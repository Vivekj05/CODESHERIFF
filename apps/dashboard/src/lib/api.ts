/**
 * The only place the dashboard talks to the backend.
 *
 * §6 makes this a rendering layer: no client secret lives here, no code is exchanged here, and
 * nothing here calls GitHub. Sign-in is a browser navigation to the FastAPI edge, which owns the
 * OAuth secret and sets an HttpOnly session cookie the JavaScript on this page cannot read.
 *
 * `credentials: "include"` on every call is what sends that cookie. The API allows exactly one
 * origin, so a page on another site cannot make these calls with the user's session.
 */

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export interface SessionInfo {
  login: string;
  name: string | null;
  avatar_url: string | null;
  installation_count: number;
  expires_at: string;
  install_url: string | null;
}

export interface RepositoryOut {
  id: number;
  full_name: string;
  default_branch: string;
  is_private: boolean;
  analysis_enabled: boolean;
}

export interface RepositoryPage {
  items: RepositoryOut[];
  next_cursor: string | null;
}

/** Thrown for any non-2xx response. `status` is what callers branch on — 401 means "sign in". */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(init.headers ?? {}) },
  });

  if (!response.ok) {
    // The API answers 501 when no GitHub App is configured. Surfacing that distinctly is the
    // difference between "you are signed out" and "this deployment was never finished".
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      // A non-JSON error body is still an error; the status carries the meaning.
    }
    throw new ApiError(response.status, detail);
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export function signInUrl(nextPath = "/repositories"): string {
  return `${API_BASE_URL}/auth/login?next=${encodeURIComponent(nextPath)}`;
}

export function getSession(): Promise<SessionInfo> {
  return request<SessionInfo>("/auth/session");
}

export function logout(): Promise<void> {
  return request<void>("/auth/logout", { method: "POST" });
}

export function listRepositories(cursor?: string | null, limit = 30): Promise<RepositoryPage> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (cursor) params.set("cursor", cursor);
  return request<RepositoryPage>(`/repositories?${params.toString()}`);
}

export function setAnalysisEnabled(
  repoId: number,
  enabled: boolean,
): Promise<RepositoryOut> {
  return request<RepositoryOut>(`/repositories/${repoId}`, {
    method: "PATCH",
    body: JSON.stringify({ analysis_enabled: enabled }),
  });
}
