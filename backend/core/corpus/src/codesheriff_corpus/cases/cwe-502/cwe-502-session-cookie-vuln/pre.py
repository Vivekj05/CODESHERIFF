def load_session(cookie_value):
    return json.loads(base64.b64decode(cookie_value))
