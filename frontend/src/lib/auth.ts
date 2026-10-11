import "server-only";

import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { nextCookies } from "better-auth/next-js";
import { jwt } from "better-auth/plugins";
import type { GithubProfile } from "better-auth/social-providers";
import { Pool } from "pg";

/**
 * Sign-in for the dashboard (D-101).
 *
 * Better Auth owns who the user is; the Python API owns everything else. The two meet in one
 * place: a short-lived JWT the dashboard sends to FastAPI, signed with a key published at
 * `/api/auth/jwks`. FastAPI verifies it and never reads these tables.
 *
 * **Visibility is still GitHub's answer (D-035).** At every sign-in the user's GitHub token is
 * spent on `GET /user/installations`, and the ids of the installations of this App that the user
 * can reach are written to `users.installation_ids`. They travel in the JWT, and every API query is
 * scoped by them. An empty list means nothing is visible, never everything.
 *
 * The GitHub provider must use the **GitHub App's** client id and secret. Only a GitHub App's
 * user token can list that user's installations of the App.
 *
 * Alembic owns the schema (`v0006_better_auth`). Better Auth's own migration CLI is not used; the
 * table and column names below must match that migration exactly.
 */

const pool = new Pool({ connectionString: databaseUrl() });

/** The API's DATABASE_URL is a SQLAlchemy URL; node-postgres wants the plain form. */
function databaseUrl(): string {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL is not set; Better Auth stores users in Postgres.");
  return url.replace(/^postgresql\+\w+:\/\//, "postgresql://");
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set. See .env.example.`);
  return value;
}

type GitHubEmail = { email: string; primary: boolean; verified: boolean };

/**
 * What GitHub said about a user, held between `getUserInfo` and the database hooks below.
 *
 * Better Auth drops every field marked `input: false` from what a provider returns, and those are
 * exactly the fields that must stay server-only: a user who could write their own
 * `installation_ids` through `/update-user` could see anybody's repositories. So the values are
 * kept here for the few milliseconds between GitHub answering and the user and session rows being
 * written, and the hooks (which run on the server and are not filtered) write them.
 *
 * Keyed by lowercased email, which Better Auth also lowercases. Entries expire after five minutes;
 * a sign-in that outlives one fails loudly rather than writing a user with no installations.
 */
type GitHubFacts = {
  githubId: number;
  login: string;
  installationIds: number[];
  storedAt: number;
};

const FACTS_TTL_MS = 5 * 60 * 1000;
const pendingFacts = new Map<string, GitHubFacts>();

function rememberFacts(email: string, facts: Omit<GitHubFacts, "storedAt">): void {
  const now = Date.now();
  for (const [key, value] of pendingFacts) {
    if (now - value.storedAt > FACTS_TTL_MS) pendingFacts.delete(key);
  }
  pendingFacts.set(email.toLowerCase(), { ...facts, storedAt: now });
}

function takeFacts(email: string | null | undefined): GitHubFacts {
  const key = (email ?? "").toLowerCase();
  const facts = pendingFacts.get(key);
  pendingFacts.delete(key);
  if (!facts || Date.now() - facts.storedAt > FACTS_TTL_MS) {
    throw new APIError("INTERNAL_SERVER_ERROR", {
      message: "GitHub's answer about this user was not available when the account was saved. Sign in again.",
    });
  }
  return facts;
}

/**
 * Who signed in, and which installations of this App they can see.
 *
 * Replaces the provider's default `getUserInfo` so that the installation list is read with the
 * same token, at the same moment, as the profile. A private primary email falls back to GitHub's
 * own no-reply address rather than failing the sign-in; it is stored unverified.
 */
async function githubUserInfo(token: { accessToken?: string }) {
  if (!token.accessToken) return null;
  const headers = {
    Authorization: `Bearer ${token.accessToken}`,
    Accept: "application/vnd.github+json",
    "User-Agent": "CodeSheriff",
  };
  const get = async <T,>(path: string): Promise<T | null> => {
    const response = await fetch(`https://api.github.com${path}`, { headers, cache: "no-store" });
    return response.ok ? ((await response.json()) as T) : null;
  };

  const profile = await get<GithubProfile>("/user");
  if (!profile) return null;

  const emails = await get<GitHubEmail[]>("/user/emails");
  const chosen = profile.email
    ? emails?.find((e) => e.email === profile.email)
    : (emails?.find((e) => e.primary) ?? emails?.[0]);
  const email = profile.email ?? chosen?.email ?? `${profile.id}+${profile.login}@users.noreply.github.com`;

  const installations = await get<{ installations: { id: number }[] }>(
    "/user/installations?per_page=100",
  );

  // A failed installations read is an empty list: the user sees nothing, never everything.
  rememberFacts(email, {
    githubId: Number(profile.id),
    login: profile.login,
    installationIds: installations?.installations.map((i) => i.id) ?? [],
  });

  return {
    // No `id` here: Better Auth keys the account on the profile's own id (`accountSubject`).
    user: {
      name: profile.name || profile.login,
      email,
      image: profile.avatar_url,
      emailVerified: chosen?.verified ?? false,
    },
    data: profile,
  };
}

export const auth = betterAuth({
  baseURL: required("BETTER_AUTH_URL"),
  secret: required("BETTER_AUTH_SECRET"),
  database: pool,
  telemetry: { enabled: false },

  databaseHooks: {
    user: {
      create: {
        // A new user: write the server-only GitHub facts the provider result could not carry.
        before: async (user) => {
          const facts = takeFacts(user.email);
          rememberFacts(user.email, facts); // the session hook below reads them once more
          return {
            data: {
              ...user,
              githubId: facts.githubId,
              login: facts.login,
              installationIds: facts.installationIds,
              lastLoginAt: new Date(),
            },
          };
        },
      },
    },
    session: {
      create: {
        // Every sign-in, new user or returning: refresh what GitHub says this user can see. This is
        // what makes an App connected since the last sign-in appear.
        before: async (session, ctx) => {
          if (!ctx) return;
          const user = await ctx.context.internalAdapter.findUserById(session.userId);
          if (!user) return;
          const facts = takeFacts(user.email);
          await ctx.context.internalAdapter.updateUser(user.id, {
            githubId: facts.githubId,
            login: facts.login,
            installationIds: facts.installationIds,
            lastLoginAt: new Date(),
          });
        },
      },
    },
  },

  socialProviders: {
    github: {
      clientId: required("GITHUB_APP_CLIENT_ID"),
      clientSecret: required("GITHUB_APP_CLIENT_SECRET"),
      getUserInfo: githubUserInfo,
      // Refresh name, avatar and above all the installation list on every sign-in.
      overrideUserInfoOnSignIn: true,
    },
  },

  user: {
    modelName: "users",
    fields: {
      emailVerified: "email_verified",
      createdAt: "created_at",
      updatedAt: "updated_at",
    },
    additionalFields: {
      // `required: false` here, NOT NULL in the database. Better Auth checks `required` against what
      // the provider returned, before any hook runs, and these are deliberately not in it: the
      // `user.create.before` hook writes them. A user without them is still refused, by Postgres.
      githubId: { type: "number", fieldName: "github_id", required: false, input: false },
      login: { type: "string", required: false, input: false },
      installationIds: { type: "number[]", fieldName: "installation_ids", required: false, input: false, defaultValue: [] },
      lastLoginAt: { type: "date", fieldName: "last_login_at", required: false, input: false },
    },
  },

  session: {
    modelName: "auth_sessions",
    // Access is a snapshot taken at sign-in, so a session is not extended indefinitely.
    expiresIn: 60 * 60 * 8,
    disableSessionRefresh: true,
    fields: {
      expiresAt: "expires_at",
      createdAt: "created_at",
      updatedAt: "updated_at",
      ipAddress: "ip_address",
      userAgent: "user_agent",
      userId: "user_id",
    },
  },

  account: {
    modelName: "auth_accounts",
    // The GitHub token is stored (Better Auth needs it to refresh), but never in the clear.
    encryptOAuthTokens: true,
    fields: {
      accountId: "account_id",
      providerId: "provider_id",
      userId: "user_id",
      accessToken: "access_token",
      refreshToken: "refresh_token",
      idToken: "id_token",
      accessTokenExpiresAt: "access_token_expires_at",
      refreshTokenExpiresAt: "refresh_token_expires_at",
      createdAt: "created_at",
      updatedAt: "updated_at",
    },
  },

  verification: {
    modelName: "auth_verifications",
    fields: {
      expiresAt: "expires_at",
      createdAt: "created_at",
      updatedAt: "updated_at",
    },
  },

  plugins: [
    jwt({
      schema: {
        jwks: {
          modelName: "auth_jwks",
          fields: {
            publicKey: "public_key",
            privateKey: "private_key",
            createdAt: "created_at",
            expiresAt: "expires_at",
          },
        },
      },
      jwt: {
        expirationTime: "15m",
        // Only what the API needs. Never the email, never a token.
        definePayload: ({ user }) => ({
          login: user.login,
          name: user.name,
          avatar_url: user.image ?? null,
          installation_ids: user.installationIds ?? [],
        }),
      },
    }),
    nextCookies(),
  ],
});
