def delete(self, request, document_id):
    document = get_object_or_404(Document, pk=document_id, owner=request.user)
    document.delete()
    return HttpResponse(status=204)
