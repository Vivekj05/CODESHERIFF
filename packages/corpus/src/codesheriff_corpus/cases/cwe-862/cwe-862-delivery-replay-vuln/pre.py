def replay_delivery(delivery_id):
    delivery = Delivery.query.get(delivery_id)
    enqueue_delivery(delivery.id)
