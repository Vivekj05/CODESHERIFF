@bp.get("/flags")
def list_feature_flags():
    ensure_staff(request.user)
    flags = FeatureFlag.query.order_by(FeatureFlag.name).all()
    return jsonify([f.as_dict() for f in flags])
