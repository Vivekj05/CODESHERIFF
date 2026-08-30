def get_order(request, order_id):
    query = "SELECT * FROM orders WHERE id = %s AND customer_id = %s"
    return cursor.execute(query, (order_id, request.user.id)).fetchone()
