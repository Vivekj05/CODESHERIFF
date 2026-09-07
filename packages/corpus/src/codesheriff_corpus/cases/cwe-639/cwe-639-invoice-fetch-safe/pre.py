def get_invoice(request, invoice_id):
    invoice = Invoice.query.filter_by(
        id=invoice_id, account_id=request.user.account_id
    ).first_or_404()
    return jsonify(invoice.as_dict())
