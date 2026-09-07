def get_user(request):
    uid = request.args.get("id")
    query = "SELECT id, email FROM users WHERE id = %s"
    return cursor.execute(query, (uid,)).fetchone()
