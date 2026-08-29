def get(self, key):
    blob = self.redis.get(self._namespaced(key))
    if blob is None:
        return None
    return pickle.loads(blob)
