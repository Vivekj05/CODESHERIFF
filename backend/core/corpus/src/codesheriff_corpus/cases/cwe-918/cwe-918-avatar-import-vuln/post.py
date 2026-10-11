def import_avatar(user, source_url):
    response = requests.get(source_url, timeout=10)
    user.avatar = response.content
    return user
