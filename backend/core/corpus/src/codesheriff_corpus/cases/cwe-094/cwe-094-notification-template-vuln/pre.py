def render_notification(template_name, user):
    return ENVIRONMENT.get_template(NOTIFICATION_TEMPLATES[template_name]).render(user=user)
