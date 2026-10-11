def checkout_branch(repo_dir, branch):
    with os.popen(f"git -C {repo_dir} checkout {branch}") as stream:
        return stream.read()
