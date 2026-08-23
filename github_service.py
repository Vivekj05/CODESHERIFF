import os
import requests
from dotenv import load_dotenv

def get_pr_files(repo_full_name: str, pr_number: int):
    """
    Fetch all changed files in a Pull Request from GitHub API.
    """
    load_dotenv()
    github_token = os.getenv("GITHUB_TOKEN")

    url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/files"

    headers = {
        "Accept": "application/vnd.github+json"
    }
    if github_token and "your_github" not in github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"⚠️ Failed to fetch PR files (HTTP {response.status_code}): {response.text}")
        return []

    return response.json()