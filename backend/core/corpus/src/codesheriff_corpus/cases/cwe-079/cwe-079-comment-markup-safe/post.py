def comment_html(comment):
    body = escape(comment.body).replace("\n", Markup("<br>"))
    return Markup('<div class="comment">') + body + Markup("</div>")
