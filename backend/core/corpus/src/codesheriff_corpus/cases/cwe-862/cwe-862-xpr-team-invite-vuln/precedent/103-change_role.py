@permission_required("team:manage")
def change_role(self, team_id, user_id, role):
    team = self.repo.get_team(team_id)
    team.set_role(user_id, role)
    self.repo.save(team)
    return team
