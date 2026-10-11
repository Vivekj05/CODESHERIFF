@bp.post("/flags/<name>")
def set_feature_flag(name):
    ensure_staff(request.user)
    enabled = request.json["enabled"]
    FeatureFlag.upsert(name, enabled=enabled)
    return jsonify(name=name, enabled=enabled)
