def check_host(request):
    host = request.args.get("host", "")
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, check=False)
    return {"exit_code": result.returncode}
