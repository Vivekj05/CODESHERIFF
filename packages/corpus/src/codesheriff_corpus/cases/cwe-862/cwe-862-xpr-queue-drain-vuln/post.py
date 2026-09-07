@bp.post("/jobs/dead-letters/drain")
def drain_dead_letters():
    drained = DeadLetter.drain(limit=500)
    return jsonify(drained=len(drained))
