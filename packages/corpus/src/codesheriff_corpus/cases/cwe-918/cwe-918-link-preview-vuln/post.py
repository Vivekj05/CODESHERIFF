def fetch(self, target):
    with urllib.request.urlopen(target, timeout=5) as stream:
        return stream.read(self.max_bytes)
