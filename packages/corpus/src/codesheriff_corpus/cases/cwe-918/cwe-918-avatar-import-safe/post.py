def import_avatar(user, source_url):
    parsed = urlparse(source_url)
    if parsed.scheme != "https" or parsed.hostname not in AVATAR_HOSTS:
        raise ValueError(f"avatar host not allowed: {parsed.hostname}")
    response = requests.get(source_url, timeout=10)
    user.avatar = response.content
    return user
