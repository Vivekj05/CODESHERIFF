def restore_backup(archive_name, target_dir):
    cmd = f"tar -xzf {archive_name} -C {target_dir}"
    return subprocess.check_output(cmd, shell=True, text=True)
