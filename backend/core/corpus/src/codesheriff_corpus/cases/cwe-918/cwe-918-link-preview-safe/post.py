def fetch(self, target):
    if self.resolve_public_address(target) is None:
        raise ValueError(f"refusing to fetch non-public target: {target}")
    with urllib.request.urlopen(target, timeout=5) as stream:
        return stream.read(self.max_bytes)
