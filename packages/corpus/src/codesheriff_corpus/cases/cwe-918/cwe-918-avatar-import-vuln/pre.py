def import_avatar(user, upload):
    user.avatar = upload.read(MAX_AVATAR_BYTES)
    return user
