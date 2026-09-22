@app.route("/admin/audit/export")
@admin_required
def export_audit_log():
    since = request.args.get("since")
    rows = AuditEntry.query.filter(AuditEntry.created_at >= since).all()
    return Response(to_csv(rows), mimetype="text/csv")
