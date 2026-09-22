def load_session(cookie_value):
    raw = base64.b64decode(cookie_value)
    return pickle.loads(raw)
