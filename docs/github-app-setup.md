# Registering the GitHub App

Chapter 5 builds the sign-in flow; this is the part only the account owner can do. Twenty minutes,
once. The settings below are the ones D-034 decided — changing them changes what the pipeline can
do, so read that entry before deviating.

## 1. Create the App

<https://github.com/settings/apps/new> (or an organisation's *Settings → Developer settings → GitHub
Apps → New GitHub App*).

| Field | Value | Notes |
|---|---|---|
| **GitHub App name** | `codesheriff-dev` (or anything free) | The slug that appears in the URL is what goes in `GITHUB_APP_SLUG` |
| **Homepage URL** | `http://localhost:3000` | Not used by the flow |
| **Callback URL** | `http://localhost:8000/auth/callback` | Must match `API_PUBLIC_URL` + `/auth/callback` **exactly**, or the code exchange fails with an unhelpful error |
| **Request user authorization (OAuth) during installation** | ✅ on | Lets the install flow and the sign-in flow be the same flow |
| **Setup URL** | `http://localhost:8000/auth/install/callback` | Where GitHub returns after an installation. It grants nothing (D-037) |
| **Redirect on update** | ✅ on | So changing the installation returns here too |
| **Webhook → Active** | ✅ on | Chapter 6 consumes these — see [`webhook-setup.md`](webhook-setup.md) |
| **Webhook URL** | a smee.io channel, e.g. `https://smee.io/aBcDeF1234` | D-043 settled §7 open question 4: smee, because the URL is permanent and needs no account |
| **Webhook secret** | `python -c "import secrets; print(secrets.token_hex(32))"` | Goes in `GITHUB_WEBHOOK_SECRET`. Unset, the webhook answers 501 and accepts nothing — it never falls back to accepting unsigned payloads (AUDIT.md 0.1) |
| **Where can this App be installed?** | Only on this account | Multi-tenancy is out of scope (§6) |

## 2. Permissions — repository level only

| Permission | Access |
|---|---|
| Metadata | Read-only |
| Contents | Read-only |
| Pull requests | Read and write |

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
- **Client ID** → `GITHUB_APP_CLIENT_ID`
- **Client secret** → *Generate a new client secret* → `GITHUB_APP_CLIENT_SECRET`
- **Private key** → *Generate a private key*, which downloads a `.pem` → put the file **outside this
  repository** and point `GITHUB_APP_PRIVATE_KEY_PATH` at it
- The slug from the App's URL (`https://github.com/settings/apps/<slug>`) → `GITHUB_APP_SLUG`

Copy `.env.example` to `.env` and fill those in. `.env` is gitignored and must stay that way.

## 5. Install it

*Install App* in the left sidebar → pick the account → choose **Only select repositories** and pick
one or two to start with. GitHub returns you to the Setup URL, which bounces through OAuth and lands
on the dashboard's repository list.

## 6. Run it

```bash
docker compose up -d postgres
uv run alembic -c packages/storage/alembic.ini upgrade head
uv run uvicorn codesheriff_api.main:app --port 8000 --reload

cd apps/dashboard && npm run dev     # http://localhost:3000
```

Open <http://localhost:3000>, which redirects to `/sign-in`.

**If the dashboard talks to the wrong API**, remember that `NEXT_PUBLIC_API_BASE_URL` is inlined at
**build time**, not read at runtime. The default is `http://localhost:8000`; changing it means
rebuilding, not just restarting.

## Checking it worked

```bash
curl -s http://localhost:8000/ | jq .auth        # "ready", not "unconfigured"
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8000/auth/session   # 401 before sign-in
```

Then sign in through the dashboard and confirm the repository list shows what the installation
grants. Signing out and back in must show the same list — that is Chapter 5's acceptance criterion,
and it is a real check: the list comes from the database, refreshed from GitHub at each sign-in.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `501` with "GITHUB_APP_CLIENT_ID … must be set" | `.env` not loaded, or the API started from a different working directory |
| GitHub error `redirect_uri_mismatch` | The Callback URL on the App is not byte-identical to `API_PUBLIC_URL` + `/auth/callback` |
| `400 OAuth state did not match` | The state cookie expired (ten minutes) or was blocked; start again from `/sign-in` |
| Signed in, but no repositories | The App is installed on an account whose installation grants no repositories, or it is installed on a *different* account from the one that signed in |
| `502 GitHub rejected the sign-in` | The client secret is wrong, or the authorisation code was already used — codes are single-use |
