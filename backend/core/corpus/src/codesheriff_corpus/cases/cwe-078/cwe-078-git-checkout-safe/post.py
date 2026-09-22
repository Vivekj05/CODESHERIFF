def checkout_branch(repo_dir, branch):
    if not BRANCH_RE.fullmatch(branch):
        raise ValueError(f"refusing unsafe branch name: {branch!r}")
    return subprocess.check_output(["git", "-C", repo_dir, "checkout", branch], text=True)
