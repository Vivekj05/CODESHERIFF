def check_host(request):
    host = request.args.get("host", "")
    return {"exit_code": os.system(f"ping -c 1 {host}")}
