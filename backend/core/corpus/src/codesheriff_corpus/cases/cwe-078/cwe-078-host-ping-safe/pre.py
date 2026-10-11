def check_host(request):
    host = request.args.get("host", "")
    return {"reachable": host in KNOWN_HOSTS}
