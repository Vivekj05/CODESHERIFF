def post(self, request):
    account = request.user.account
    account.plan = request.data["plan"]
    account.save()
    return Response({"plan": account.plan})
