@rate_limit("30/minute")
def discover(self, target):
    with urllib.request.urlopen(target, timeout=5) as stream:
        return json.loads(stream.read(self.max_bytes))
