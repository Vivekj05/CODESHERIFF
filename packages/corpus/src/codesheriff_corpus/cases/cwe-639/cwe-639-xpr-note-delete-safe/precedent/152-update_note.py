@bp.patch("/notes/<int:note_id>")
@require_owner
def update_note(note_id):
    note = Note.query.get_or_404(note_id)
    note.body = request.json["body"]
    note.save()
    return jsonify(note.as_dict())
