def render_profile(request, user):
    bio = user.bio or ""
    return Response(f"<section>{escape(bio)}</section>", mimetype="text/html")
