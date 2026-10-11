@bp.post("/internal/jobs/<int:job_id>/cancel")
@requires_scope("internal")
def cancel_job(job_id):
    job = Job.query.get_or_404(job_id)
    job.cancel()
    return jsonify(status="cancelled", job_id=job.id)
