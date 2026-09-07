def render_search_header(request):
    term = request.args.get("q", "")
    return Response(f"<h2>Results for {escape(term)}</h2>", mimetype="text/html")
