def serve_avatar(request, filename):
    return send_file(UPLOAD_DIR + "/" + filename)
