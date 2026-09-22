@bp.get("/attachments/<int:attachment_id>")
@require_owner("attachment_id")
def get_attachment(attachment_id):
    attachment = Attachment.query.get_or_404(attachment_id)
    return jsonify(attachment.as_dict())
