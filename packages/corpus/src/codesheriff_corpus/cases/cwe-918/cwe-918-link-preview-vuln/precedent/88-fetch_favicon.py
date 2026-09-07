@rate_limit("30/minute")
def fetch_favicon(self, target):
    with urllib.request.urlopen(target, timeout=5) as stream:
        return stream.read(4096)
