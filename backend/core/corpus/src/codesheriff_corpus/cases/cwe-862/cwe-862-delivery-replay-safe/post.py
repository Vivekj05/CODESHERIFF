def replay_delivery(request, delivery_id):
    if not request.user.has_permission("deliveries:replay"):
        abort(403)
    delivery = Delivery.query.get_or_404(delivery_id)
    enqueue_delivery(delivery.id)
    return jsonify({"status": "queued", "delivery": delivery.id})
