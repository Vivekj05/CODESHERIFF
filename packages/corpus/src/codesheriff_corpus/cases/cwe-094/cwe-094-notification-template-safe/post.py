def render_notification(template_name, user):
    if template_name not in NOTIFICATION_TEMPLATES:
        raise KeyError(template_name)
    template = ENVIRONMENT.get_template(NOTIFICATION_TEMPLATES[template_name])
    return template.render(user=user, rendered_at=utcnow())
