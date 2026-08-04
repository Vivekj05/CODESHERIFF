from fastapi import FastAPI, Request
import requests
import os
from dotenv import load_dotenv

load_dotenv()
app = FastAPI()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

@app.post("/webhook")
async def webhook(request: Request):
    payload = await request.json()

    if payload.get("action") == "opened" and "pull_request" in payload:
        pr = payload["pull_request"]
        repo_full_name = payload["repository"]["full_name"]
        pr_number = pr["number"]

        print(f"New PR opened: #{pr_number} in {repo_full_name}")

        comment_url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
        headers = {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json"
        }
        body = {"body": "🔍 CodeSheriff audit: (placeholder — pipeline not wired yet)"}
        response = requests.post(comment_url, headers=headers, json=body)
        print("Comment post status:", response.status_code)

    return {"status": "received"}