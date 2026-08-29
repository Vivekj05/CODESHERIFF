def test_webhook(request):
    url = request.get_json()["url"]
    if not is_public_https_url(url):
        abort(400, "webhook URLs must be public HTTPS endpoints")
    response = requests.post(url, json={"ping": True}, timeout=5, allow_redirects=False)
    return {"status": response.status_code}
