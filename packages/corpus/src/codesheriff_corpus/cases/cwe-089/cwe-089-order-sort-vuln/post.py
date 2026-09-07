def list_orders(request):
    sort = request.args.get("sort", "created_at")
    query = "SELECT * FROM orders WHERE customer_id = %s ORDER BY " + sort
    return cursor.execute(query, (request.user.id,)).fetchall()
