def apply_rule(rule, record):
    namespace = {"record": record}
    exec(rule.body, {"__builtins__": {}}, namespace)
    return namespace.get("result")
