def render_notification(template_source, user):
    return Template(template_source).render(user=user)
