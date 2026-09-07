def serve_avatar(request, filename):
    safe_name = secure_filename(filename)
    if not safe_name:
        abort(400)
    return send_file(os.path.join(UPLOAD_DIR, safe_name))
