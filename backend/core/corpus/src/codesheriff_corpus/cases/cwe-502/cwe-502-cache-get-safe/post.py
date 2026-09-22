def get(self, key):
    blob = self.redis.get(self._namespaced(key))
    if blob is None:
        self.misses += 1
        return None
    return json.loads(blob.decode("utf-8"))
