def search(self, term):
    return self.session.query(Article).filter(Article.title.contains(term)).all()
