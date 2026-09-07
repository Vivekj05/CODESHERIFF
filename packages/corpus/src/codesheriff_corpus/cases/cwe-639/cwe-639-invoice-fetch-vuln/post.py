def get_invoice(request, invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    return jsonify(invoice.as_dict())
