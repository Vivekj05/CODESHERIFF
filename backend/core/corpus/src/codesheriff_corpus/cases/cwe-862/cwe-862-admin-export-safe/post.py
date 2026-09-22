@app.route("/admin/users/export")
@admin_required
def export_users():
    rows = User.query.order_by(User.created_at).all()
    return Response(to_csv(rows), mimetype="text/csv")
