def delete(self, template_name):
    target = os.path.join(self.template_dir, template_name)
    os.remove(target)
    self.log.info("removed template %s", template_name)
