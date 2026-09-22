def delete(self, request, document_id):
    document = Document.objects.get(pk=document_id)
    document.delete()
    return HttpResponse(status=204)
