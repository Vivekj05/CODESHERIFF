@bp.delete("/flags/<name>")
def delete_feature_flag(name):
    ensure_staff(request.user)
    FeatureFlag.delete(name)
    return jsonify(name=name, deleted=True)
