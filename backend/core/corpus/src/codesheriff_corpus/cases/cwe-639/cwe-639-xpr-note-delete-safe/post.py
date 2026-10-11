@bp.delete("/notes/<int:note_id>")
@require_owner
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    note.delete()
    return jsonify(deleted=note_id)
