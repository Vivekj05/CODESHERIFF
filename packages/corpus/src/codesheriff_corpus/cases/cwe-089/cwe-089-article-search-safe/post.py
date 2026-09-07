def search(self, term):
    statement = text("SELECT id, title FROM articles WHERE title LIKE :pattern")
    return self.session.execute(statement, {"pattern": f"%{term}%"}).all()
