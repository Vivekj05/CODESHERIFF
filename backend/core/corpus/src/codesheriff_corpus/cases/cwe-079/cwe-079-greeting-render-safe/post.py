def render_greeting(request):
    name = request.args.get("name", "friend")
    return Response(f"<h1>Hello {escape(name)}</h1>", mimetype="text/html")
