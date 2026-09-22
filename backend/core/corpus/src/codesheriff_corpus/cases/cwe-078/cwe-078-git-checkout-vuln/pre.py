def checkout_branch(repo_dir, branch):
    repo = git.Repo(repo_dir)
    repo.git.checkout(branch)
    return repo.head.commit.hexsha
