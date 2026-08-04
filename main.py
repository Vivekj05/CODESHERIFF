from fastapi import FastAPI, Request
import requests
import os
from dotenv import load_dotenv

from github_service import get_pr_files

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

        print("=" * 60)
        print(f"Repository : {repo_full_name}")
        print(f"PR Number  : {pr_number}")
        print(f"Title      : {pr['title']}")
        print("=" * 60)

        # Fetch changed files
        files = get_pr_files(repo_full_name, pr_number)

        print(f"\nFiles Changed: {len(files)}\n")

        for idx, file in enumerate(files, start=1):

            print(f"File {idx}")
            print(f"Filename   : {file['filename']}")
            print(f"Status     : {file['status']}")
            print(f"Additions  : {file['additions']}")
            print(f"Deletions  : {file['deletions']}")
            print(f"Changes    : {file['changes']}")

            patch = file.get("patch", "No patch available")

            print("\nPatch:")
            print("-" * 50)
            print(patch)
            print("-" * 50)
            print()

        # Placeholder comment
        comment_url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"

        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json"
        }

        body = {
            "body": "🔍 CodeSheriff received the PR and extracted the diff successfully."
        }

        response = requests.post(comment_url, headers=headers, json=body)

        print("Comment Status:", response.status_code)

    return {"status": "received"}