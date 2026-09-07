def download_report(request):
    report = Report.query.get_or_404(request.args.get("id"))
    with open(report.stored_path, "rb") as handle:
        return Response(handle.read(), mimetype="application/pdf")
