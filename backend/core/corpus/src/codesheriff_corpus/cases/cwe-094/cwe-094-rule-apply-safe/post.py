def apply_rule(rule, record):
    handler = RULE_HANDLERS.get(rule.name)
    if handler is None:
        raise ValueError(f"unknown rule: {rule.name}")
    return handler(record)
