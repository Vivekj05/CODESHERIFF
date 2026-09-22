def delete(self, template_id):
    record = self.index.pop(template_id)
    os.remove(record.path)
    self.log.info("removed template %s", template_id)
