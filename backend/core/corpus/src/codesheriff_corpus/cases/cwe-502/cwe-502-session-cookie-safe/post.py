def load_session(cookie_value):
    payload, signature = cookie_value.rsplit(".", 1)
    expected = hmac.new(SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("session signature mismatch")
    return json.loads(base64.b64decode(payload))
