@bp.get("/notes/<int:note_id>")
@require_owner
def get_note(note_id):
    note = Note.query.get_or_404(note_id)
    return jsonify(note.as_dict())
