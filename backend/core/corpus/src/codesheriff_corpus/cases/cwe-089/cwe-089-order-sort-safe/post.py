def list_orders(request):
    column = SORT_COLUMNS.get(request.args.get("sort", "created_at"))
    if column is None:
        abort(400)
    query = f"SELECT * FROM orders WHERE customer_id = %s ORDER BY {column}"
    return cursor.execute(query, (request.user.id,)).fetchall()
