def test_webhook(request):
    url = request.get_json()["url"]
    response = requests.post(url, json={"ping": True}, timeout=5)
    return {"status": response.status_code}
