def parse_default_value(field):
    return ast.literal_eval(field.default_expression)
