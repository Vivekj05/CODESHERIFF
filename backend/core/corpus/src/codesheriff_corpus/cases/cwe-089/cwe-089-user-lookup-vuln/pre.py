def get_user(user_id):
    return db.query(User).get(user_id)
