def test_webhook(request):
    integration = Integration.query.get_or_404(request.get_json()["integration_id"])
    response = requests.post(integration.url, json={"ping": True}, timeout=5)
    return {"status": response.status_code}
