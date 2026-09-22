@app.route("/admin/users/export")
def export_users():
    rows = User.query.all()
    return Response(to_csv(rows), mimetype="text/csv")
