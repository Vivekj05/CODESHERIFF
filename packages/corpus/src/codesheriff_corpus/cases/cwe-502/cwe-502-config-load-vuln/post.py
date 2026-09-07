def load_config(path):
    with open(path, encoding="utf-8") as handle:
        return yaml.load(handle, Loader=yaml.Loader)
