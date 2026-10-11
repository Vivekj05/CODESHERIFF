# CodeSheriff dashboard

The Next.js 16 front end for CodeSheriff: the public home page, GitHub sign-in, and the dashboard
that shows what every audit found and how each probability was reached. It is a separate npm
project, not a member of the Python `uv` workspace.

The analysis, the data and every number on screen come from the Python API (`backend/api`). This
app renders them, and runs sign-in. It computes no probability and calls GitHub only to sign a
user in.

---

## Pages

| Route | What it is |
|---|---|
| `/` | Public home page. Only measured numbers; the example finding multiplies the real fitted ratios. |
| `/sign-in` | One card, "Continue with GitHub". `?next=` returns the user where they were going; `?refresh=1` re-runs sign-in after an App install to pick up new installations. |
| `/overview` | Counts of what happened, the GitHub App's state, the calibration in force, and what each witness has said. Prompts to connect the App until one is connected. |
| `/repositories` | Repositories the App can read, with search, filters and a per-repository analysis switch. |
| `/github-app` | Connect, manage or disconnect the GitHub App. Every action is a link to GitHub's own pages. |
| `/audits`, `/audits/[id]` | Audit history; one audit's findings and every witness's statement per function. |
| `/audits/[id]/findings/[key]` | One finding's odds product, factor by factor, as the run stored it. |
| `/calibration` | Reliability bins, per-cell observation counts and the whole threshold sweep. |
| `/settings` | Profile (from the GitHub sign-in, read-only) and Analysis (the fixed threshold, witnesses and CWE scope). |

Everything under `(protected)` renders inside the signed-in shell; a visitor without a session is
sent to `/sign-in?next=<where they were going>`.

---

## Sign-in (D-101)

Better Auth runs in this app (`src/lib/auth.ts`), with the **GitHub App's** client id and secret,
mounted at `/api/auth/*`, the only Next.js API route in the project.

- At every sign-in the user's GitHub token reads `GET /user/installations`. The ids are written to
  `users.installation_ids` by server-side database hooks, never taken from the browser, so a user
  cannot widen what they see.
- Better Auth's JWT plugin issues a 15-minute EdDSA token carrying the login, name, avatar and
  installation ids (never the email or a GitHub token). `src/lib/api.ts` attaches it to every API
  call; the API verifies it against `/api/auth/jwks`.
- The GitHub token is stored in `auth_accounts`, encrypted with `BETTER_AUTH_SECRET`.
- Alembic owns Better Auth's tables (migration `0006_better_auth`). **Do not run `npx auth migrate`.**

## Design

Built with [ChaiUI](https://ui.chaicode.com): its components are installed under
`src/components/chai` so the existing Base UI components in `src/components/ui` are untouched. The
logo is CodeSheriff's own (`brand-logo.tsx`), not ChaiCode's. Dark is the default theme.

Rules the code keeps, from the project's invariants:

1. **No probability reaches the screen bare.** Every posterior renders through `<Posterior>`, with
   the calibration it ran under.
2. **Silence and abstention stay distinct.** An agent that ran and found nothing and an agent that
   could not run are different statements, and are shown as such.
3. **No invented content.** No template reviews, generated diffs or placeholder charts: if the
   backend did not record it, the page does not show it.

---

## Layout

```
src/
├── app/
│   ├── (protected)/              # signed-in pages (see the table above)
│   ├── api/auth/[...all]/        # Better Auth: sign-in, callback, sign-out, token, JWKS
│   ├── sign-in/                  # the sign-in card
│   ├── layout.tsx                # theme script, providers
│   └── page.tsx                  # home page
├── components/
│   ├── chai/                     # ChaiUI primitives (button, card, chip, tabs, ...)
│   ├── ui/                       # Base UI / shadcn primitives, restyled
│   ├── landing/                  # home page pieces (example finding, reveal)
│   ├── app-shell.tsx, app-sidebar.tsx, session-gate.tsx
│   ├── posterior.tsx, evidence-kind-badge.tsx, page-header.tsx, github-mark.tsx
│   └── navbar.tsx, hero.tsx, footer.tsx, ...   # ChaiUI blocks
└── lib/
    ├── auth.ts                   # Better Auth server config (server-only)
    ├── auth-client.ts            # Better Auth in the browser
    ├── api.ts                    # the only caller of the Python API
    └── types.ts                  # contract v2.0.0 types
```

---

## Running locally

Needs Node 20+, the Python API on `http://localhost:8000`, and Postgres (Better Auth stores users
there). From the repository root, `codesheriff.bat dev` starts everything; or here:

```bash
npm install
npm run dev        # http://localhost:3000
npm run lint       # gate
npm run build      # gate: type-check and production build
```

### `.env.local`

```ini
# The Python API. Inlined at BUILD time: changing it means rebuilding.
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000

# Better Auth
BETTER_AUTH_URL=http://localhost:3000
BETTER_AUTH_SECRET=<32+ random bytes>
DATABASE_URL=postgresql://codesheriff:codesheriff@localhost:5432/codesheriff
GITHUB_APP_CLIENT_ID=<the GitHub App's client id>
GITHUB_APP_CLIENT_SECRET=<the GitHub App's client secret>
```

The GitHub App needs the callback URL `http://localhost:3000/api/auth/callback/github` and the
"Email addresses: Read-only" account permission; see `docs/github-app-setup.md`.

This version of Next.js differs from older ones in places (see `AGENTS.md`); its own docs in
`node_modules/next/dist/docs/` are the reference.
