def update_profile(request):
    payload = request.get_json()
    user = User.query.get_or_404(request.user.id)
    user.display_name = payload["display_name"]
    db.session.commit()
    return jsonify(user.as_dict())
