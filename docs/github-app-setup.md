# Registering the GitHub App

Sign-in (Better Auth, D-101) and connecting repositories (the GitHub App page, D-102) both run
through this App; registering it is the part only the account owner can do. Twenty minutes, once. The settings below are the ones D-034 decided — changing them changes what the pipeline can
do, so read that entry before deviating.

## 1. Create the App

<https://github.com/settings/apps/new> (or an organisation's *Settings → Developer settings → GitHub
Apps → New GitHub App*).

| Field | Value | Notes |
|---|---|---|
| **GitHub App name** | `codesheriff-dev` (or anything free) | The slug that appears in the URL is what goes in `GITHUB_APP_SLUG` |
| **Homepage URL** | `http://localhost:3000` | Not used by the flow |
| **Callback URL** | `http://localhost:3000/api/auth/callback/github` | Better Auth's GitHub callback in the dashboard (D-101). Must match `BETTER_AUTH_URL` + `/api/auth/callback/github` **exactly** |
| **Request user authorization (OAuth) during installation** | ⬜ **off** | Signing in and connecting are separate steps (D-102). Left on, GitHub ignores the Setup URL and sends the user to the *first* callback URL instead |
| **Setup URL** | `http://localhost:8000/auth/install/callback` | Where GitHub returns after an installation. It grants nothing (D-037): it sends the user through a silent re-sign-in to the GitHub App page |
| **Redirect on update** | ✅ on | So changing the installation returns here too |
| **Webhook → Active** | ✅ on | Chapter 6 consumes these — see [`webhook-setup.md`](webhook-setup.md) |
| **Webhook URL** | a smee.io channel, e.g. `https://smee.io/aBcDeF1234` | D-043 settled §7 open question 4: smee, because the URL is permanent and needs no account |
| **Webhook secret** | `python -c "import secrets; print(secrets.token_hex(32))"` | Goes in `GITHUB_WEBHOOK_SECRET`. Unset, the webhook answers 501 and accepts nothing — it never falls back to accepting unsigned payloads (AUDIT.md 0.1) |
| **Where can this App be installed?** | Only on this account | Multi-tenancy is out of scope (§6) |

## 2. Permissions

| Permission | Access |
|---|---|
| Metadata | Read-only |
| Contents | Read-only |
| Pull requests | Read and write |

Plus one **account** permission: **Email addresses: Read-only.** Better Auth requires an email for
every user and reads a private one through it (D-101); without it, sign-in fails for anyone whose
email is private.

**Nothing else.** No Checks, no Actions, no Administration, no Members, and no Contents: write.
CodeSheriff never pushes code — patches are suggestions inside a comment (D-034). Every extra
permission is a capability a compromised App would carry.

## 3. Events

Subscribe to exactly three:

- `Pull request`
- `Installation`
- `Installation repositories`

Not `Push`. A force-push to a PR branch already arrives as `pull_request` / `synchronize`.

## 4. Collect the credentials

From the App's settings page after creating it:

- **App ID** → `GITHUB_APP_ID`
- **Client ID** → `GITHUB_APP_CLIENT_ID`, in **`frontend/.env.local`** (sign-in runs there, D-101)
- **Client secret** → *Generate a new client secret* → `GITHUB_APP_CLIENT_SECRET`, also in
  `frontend/.env.local`
- **Private key** → *Generate a private key*, which downloads a `.pem` → put the file **outside this
  repository** and point `GITHUB_APP_PRIVATE_KEY_PATH` at it
- The slug from the App's URL (`https://github.com/settings/apps/<slug>`) → `GITHUB_APP_SLUG`

Copy `.env.example` to `.env` and fill those in. `.env` is gitignored and must stay that way.

## 5. Install it

Sign in at <http://localhost:3000/sign-in>, open the dashboard's **GitHub App** page and choose
**Install GitHub App** (or use *Install App* in the App's own settings). Pick the account, choose
**Only select repositories** and pick one or two to start with. GitHub returns you to the Setup URL,
which re-runs sign-in silently so the new installation is picked up, and lands on the GitHub App
page showing **Connected**.

Changing the selection later, from **Manage repositories**, is picked up by the
`installation_repositories` webhook, so the webhook forwarder must be running (see
[`webhook-setup.md`](webhook-setup.md)).

## 6. Run it

The client id and secret go in **`frontend/.env.local`**, with Better Auth's own settings; the
full list is at the bottom of `.env.example`. Then:

```bash
docker compose up -d postgres redis
uv run alembic -c backend/core/storage/alembic.ini upgrade head
uv run uvicorn codesheriff_api.main:app --port 8000 --reload

cd frontend && npm run dev     # http://localhost:3000
```

On Windows, `codesheriff.bat dev` starts all of it, plus the worker and the webhook forwarder.
Open <http://localhost:3000> and choose **Sign in**.

**If the dashboard talks to the wrong API**, remember that `NEXT_PUBLIC_API_BASE_URL` is inlined at
**build time**, not read at runtime. The default is `http://localhost:8000`; changing it means
rebuilding, not just restarting.

## Checking it worked

```bash
curl -s http://localhost:3000/api/auth/jwks                                    # an Ed25519 key
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8000/auth/session   # 401 without a token
```

Then sign in, and confirm the GitHub App page shows **Connected** and Repositories shows what the
installation grants. Signing out and back in must show the same list: Chapter 5's acceptance
criterion, and a real check, because the list comes from the database and the installation ids
are re-read from GitHub at each sign-in.

## Troubleshooting

| Symptom | Cause |
|---|---|
| The dashboard fails to start: "… is not set. See .env.example." | `frontend/.env.local` lacks a Better Auth variable (`BETTER_AUTH_URL`, `BETTER_AUTH_SECRET`, `DATABASE_URL`, `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET`) |
| GitHub: "The `redirect_uri` is not associated with this application" | The Callback URL on the App is not byte-identical to `BETTER_AUTH_URL` + `/api/auth/callback/github` |
| After installing or changing repositories, you land on `localhost:8000/auth/callback` | "Request user authorization (OAuth) during installation" is on, and an old callback URL is listed first. Turn it off; that URL now redirects to the re-sign-in anyway |
| Better Auth error `MISSING_FIELD … is required` | A `users` field marked `required` in `auth.ts` that the database hooks write; keep those `required: false` |
| Changed repositories on GitHub, nothing changed in the dashboard | The webhook forwarder (smee) was not running; smee keeps nothing. Redeliver from the App's *Advanced* tab, or sign in again |
| Signed in, but no repositories | The App is installed on an account whose installation grants no repositories, or it is installed on a *different* account from the one that signed in |
| Better Auth error `email_not_found` | The App lacks the "Email addresses: Read-only" account permission |
