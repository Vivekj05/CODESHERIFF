def list_orders(request):
    query = "SELECT * FROM orders WHERE customer_id = %s ORDER BY created_at"
    return cursor.execute(query, (request.user.id,)).fetchall()
