def comment_html(comment):
    body = comment.body.replace("\n", "<br>")
    return Markup(f'<div class="comment">{body}</div>')
