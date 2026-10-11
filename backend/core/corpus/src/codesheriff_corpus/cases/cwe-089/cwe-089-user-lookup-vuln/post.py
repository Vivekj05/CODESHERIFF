def get_user(request):
    uid = request.args.get("id")
    query = f"SELECT id, email FROM users WHERE id = {uid}"
    return cursor.execute(query).fetchone()
