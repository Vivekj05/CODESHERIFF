def download_report(request):
    name = request.args.get("name", "")
    root = Path(REPORT_ROOT).resolve()
    path = (root / name).resolve()
    if not path.is_relative_to(root):
        abort(404)
    with open(path, "rb") as handle:
        return Response(handle.read(), mimetype="application/pdf")
