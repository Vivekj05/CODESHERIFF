@bp.get("/internal/webhooks/deliveries")
@requires_scope("internal")
def list_deliveries():
    deliveries = Delivery.query.order_by(Delivery.created_at.desc()).limit(100).all()
    return jsonify([d.as_dict() for d in deliveries])
