def fetch(self, target):
    cached = self.cache.get(target)
    if cached is None:
        raise KeyError(target)
    return cached
