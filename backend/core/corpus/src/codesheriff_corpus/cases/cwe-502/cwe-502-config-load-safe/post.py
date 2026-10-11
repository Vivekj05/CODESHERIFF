def load_config(path):
    with open(path, encoding="utf-8") as handle:
        document = yaml.safe_load(handle)
    return document if isinstance(document, dict) else {}
