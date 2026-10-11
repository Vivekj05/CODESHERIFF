def sign_token(claims):
    secret = os.environ.get("JWT_SECRET", "dev-secret-do-not-use")
    return jwt.encode(claims, secret, algorithm="HS256")
