@app.route("/admin/billing/export")
@admin_required
def export_invoices():
    rows = Invoice.query.order_by(Invoice.issued_at).all()
    return Response(to_csv(rows), mimetype="text/csv")
