@bp.get("/attachments/<int:attachment_id>/download")
def download_attachment(attachment_id):
    attachment = Attachment.query.get_or_404(attachment_id)
    return send_file(attachment.stored_path, download_name=attachment.filename)
