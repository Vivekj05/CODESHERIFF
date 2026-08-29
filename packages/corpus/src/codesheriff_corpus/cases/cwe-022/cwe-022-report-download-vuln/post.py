def download_report(request):
    name = request.args.get("name", "")
    path = os.path.join(REPORT_ROOT, name)
    with open(path, "rb") as handle:
        return Response(handle.read(), mimetype="application/pdf")
