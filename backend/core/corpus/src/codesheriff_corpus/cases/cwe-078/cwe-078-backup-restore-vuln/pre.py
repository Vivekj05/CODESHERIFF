def restore_backup(archive_name, target_dir):
    shutil.unpack_archive(os.path.join(BACKUP_ROOT, archive_name), target_dir)
    return "ok"
