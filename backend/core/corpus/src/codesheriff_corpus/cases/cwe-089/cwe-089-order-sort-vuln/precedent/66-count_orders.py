def count_orders(request):
    query = "SELECT COUNT(*) FROM orders WHERE customer_id = %s"
    return cursor.execute(query, (request.user.id,)).fetchone()[0]
