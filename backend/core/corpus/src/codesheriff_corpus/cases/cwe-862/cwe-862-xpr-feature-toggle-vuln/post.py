@bp.post("/flags/<name>")
def set_feature_flag(name):
    enabled = request.json["enabled"]
    FeatureFlag.upsert(name, enabled=enabled)
    return jsonify(name=name, enabled=enabled)
