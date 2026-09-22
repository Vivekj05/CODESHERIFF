def render_greeting(request):
    name = request.args.get("name", "friend")
    return render_template("greeting.html", name=name)
