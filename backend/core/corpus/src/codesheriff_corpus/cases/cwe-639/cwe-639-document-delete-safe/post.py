def delete(self, request, document_id):
    document = get_object_or_404(Document, pk=document_id, owner=request.user)
    document.deleted_at = timezone.now()
    document.save(update_fields=["deleted_at"])
    return HttpResponse(status=204)
