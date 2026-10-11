@bp.post("/internal/webhooks/<int:delivery_id>/replay")
@requires_scope("internal")
def replay_delivery(delivery_id):
    delivery = Delivery.query.get_or_404(delivery_id)
    enqueue_delivery(delivery.endpoint, delivery.payload)
    return jsonify(status="queued", delivery_id=delivery.id)
