def apply_rule(rule, record):
    handler = RULE_HANDLERS[rule.name]
    return handler(record)
