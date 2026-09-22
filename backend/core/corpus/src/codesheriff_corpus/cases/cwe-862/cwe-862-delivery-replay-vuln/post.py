def replay_delivery(request, delivery_id):
    delivery = Delivery.query.get_or_404(delivery_id)
    enqueue_delivery(delivery.id)
    return jsonify({"status": "queued", "delivery": delivery.id})
