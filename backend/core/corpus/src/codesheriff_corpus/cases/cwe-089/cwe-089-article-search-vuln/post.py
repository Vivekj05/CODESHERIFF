def search(self, term):
    statement = text(f"SELECT id, title FROM articles WHERE title LIKE '%{term}%'")
    return self.session.execute(statement).all()
