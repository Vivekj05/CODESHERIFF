def delete(self, template_name):
    if template_name not in self.known_templates():
        raise KeyError(template_name)
    os.remove(os.path.join(self.template_dir, template_name))
    self.log.info("removed template %s", template_name)
