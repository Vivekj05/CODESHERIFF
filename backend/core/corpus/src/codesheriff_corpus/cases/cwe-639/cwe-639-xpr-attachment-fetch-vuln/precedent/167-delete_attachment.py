@bp.delete("/attachments/<int:attachment_id>")
@require_owner("attachment_id")
def delete_attachment(attachment_id):
    attachment = Attachment.query.get_or_404(attachment_id)
    attachment.delete()
    return jsonify(deleted=attachment_id)
