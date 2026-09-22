@permission_required("team:manage")
def remove_member(self, team_id, user_id):
    team = self.repo.get_team(team_id)
    team.members.remove(user_id)
    self.repo.save(team)
    return team
