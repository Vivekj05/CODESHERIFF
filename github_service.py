import os
import requests
from dotenv import load_dotenv
load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
print("Token:", GITHUB_TOKEN)

def get_pr_files(repo_full_name: str, pr_number: int):
    """
    Fetch all changed files in a Pull Request.
    """

    url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/files"

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print("Failed to fetch PR files")
        print(response.text)
        return []

    return response.json()