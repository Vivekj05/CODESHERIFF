def restore_backup(archive_name, target_dir):
    return subprocess.check_output(
        ["tar", "-xzf", archive_name, "-C", target_dir], text=True
    )
