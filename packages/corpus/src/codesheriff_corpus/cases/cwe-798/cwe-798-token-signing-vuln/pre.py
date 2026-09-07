def sign_token(claims):
    return jwt.encode(claims, os.environ["JWT_SECRET"], algorithm="HS256")
