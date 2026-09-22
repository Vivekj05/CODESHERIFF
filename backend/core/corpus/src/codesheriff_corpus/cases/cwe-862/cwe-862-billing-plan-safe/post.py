def post(self, request):
    if not request.user.is_billing_admin:
        raise PermissionDenied("billing admin required")
    account = request.user.account
    if request.data["plan"] not in AVAILABLE_PLANS:
        raise ValidationError("unknown plan")
    account.plan = request.data["plan"]
    account.save()
    return Response({"plan": account.plan})
