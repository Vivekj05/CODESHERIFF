def sign_token(claims):
    secret = os.environ["JWT_SECRET"]
    claims = {**claims, "exp": utcnow() + TOKEN_LIFETIME}
    return jwt.encode(claims, secret, algorithm="HS256")
