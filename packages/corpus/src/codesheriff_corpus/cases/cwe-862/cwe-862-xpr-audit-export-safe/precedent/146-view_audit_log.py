@app.route("/admin/audit")
@admin_required
def view_audit_log():
    rows = AuditEntry.query.order_by(AuditEntry.created_at.desc()).limit(200).all()
    return render_template("audit.html", rows=rows)
