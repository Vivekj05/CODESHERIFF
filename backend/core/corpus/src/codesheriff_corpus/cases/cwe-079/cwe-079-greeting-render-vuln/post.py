def render_greeting(request):
    name = request.args.get("name", "friend")
    return Response(f"<h1>Hello {name}</h1>", mimetype="text/html")
