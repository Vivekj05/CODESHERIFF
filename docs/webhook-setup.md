# Receiving webhooks locally

Twenty minutes, once. After this, opening a pull request on a connected repository produces a
CodeSheriff comment on it.

Prerequisite: a registered GitHub App with the D-034 permissions —
[`github-app-setup.md`](github-app-setup.md) walks through that. This document covers only the
delivery path.

---

## 1. Open a smee channel

```bash
# Visit https://smee.io and press "Start a new channel". No account, no sign-up.
# Copy the URL it gives you — e.g. https://smee.io/aBcDeF1234
```

smee rather than ngrok, per D-043: the channel URL is permanent, so the App's webhook URL is
entered once and never again. ngrok's free tier issues a new URL per session unless you create an
account and claim a static domain, and a stale webhook URL means deliveries that silently go
nowhere.

Reach for ngrok when a signature verifies in tests and fails against GitHub. That is almost always a
body-encoding difference, and ngrok's inspector shows the full request while smee does not.

## 2. Point the App at it

In the App's settings (**Webhook** section):

| Field | Value |
|---|---|
| Active | ✅ on |
| Webhook URL | your smee channel URL, e.g. `https://smee.io/aBcDeF1234` |
| Webhook secret | generate one and paste it — see below |

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Put the same value in `.env` as `GITHUB_WEBHOOK_SECRET`. The two must match exactly; a trailing
newline is a mismatch.

**Without the secret the webhook accepts nothing.** It answers `501` naming the missing variable
rather than falling back to accepting unsigned payloads — the failure mode `AUDIT.md` 0.1
documents. A 5xx also means GitHub redelivers, so deliveries that arrive before the secret is set
are not lost.

Confirm the subscribed events are `pull_request`, `installation` and `installation_repositories`,
and nothing else (D-034). Not `push`: a force-push to a PR branch already arrives as `pull_request`
with action `synchronize`.

## 3. Run the four processes

```bash
docker compose up -d postgres redis
uv run alembic -c packages/storage/alembic.ini upgrade head

uv run uvicorn codesheriff_api.main:app --reload
uv run celery -A codesheriff_worker.celery_app worker --loglevel=info --queues=audits
npx smee-client --url https://smee.io/<channel> --path /webhooks/github --port 8000
```

`GET http://localhost:8000/` reports whether each half is configured:

```json
{"auth": "ready", "webhook": "ready"}
```

`"unconfigured"` on either means a missing environment variable, not a broken install.

## 4. Prove it

Open a pull request on a repository the App is installed on. Expect, in order:

1. **smee's terminal** logs a forwarded `pull_request` delivery.
2. **The API** logs `Queued audit <uuid> for owner/repo#N at <sha>` and answers 202. Under three
   seconds — GitHub's hard limit is ten, and the pipeline it starts takes minutes.
3. **The worker** logs `Audit <uuid> finished: owner/repo#N, comment <id>`.
4. **The pull request** carries one CodeSheriff comment saying no analysis has run yet, with every
   backend listed as having abstained.

Push again to the same branch. The comment is **edited in place**, not duplicated (D-034), and the
previous audit moves to `superseded` rather than `failed` — being overtaken is not a failure
(D-039).

```sql
SELECT pr_number, left(head_sha, 7) AS head, status, github_comment_id
FROM audits ORDER BY created_at;
```

---

## When it does not work

**Nothing reaches smee.** The App's webhook is off, or the URL has a typo. GitHub records every
attempt under the App's **Advanced → Recent Deliveries**, with the response it got — start there.

**smee forwards, the API answers 401.** The secrets differ. Recreate `GITHUB_WEBHOOK_SECRET` from
the App's settings and restart the API; the value is read at startup. Check for a trailing newline
if you piped it into the file.

**The API answers 501.** `GITHUB_WEBHOOK_SECRET` is unset. Deliveries are not lost — fix it and use
**Redeliver** on the delivery in GitHub's UI.

**202, but no comment ever appears.** The worker is not consuming. Check it is running against the
same broker *and the same queue name* (`--queues=audits`), and look for the audit row: `status`
tells you where it stopped, and `error_reason` says why if it failed. A row stuck at `queued` with a
worker running usually means the two disagree about the queue name.

**403 from GitHub in the worker's log.** The installation lacks Pull requests: write. Permission
changes need to be accepted on the installation — GitHub emails the account owner a link.

**Deliveries arrive twice.** They are meant to; GitHub delivers at least once. The second one
answers `202 duplicate` and opens no second audit (D-038). If you see two comments, that is a bug
worth reporting.
