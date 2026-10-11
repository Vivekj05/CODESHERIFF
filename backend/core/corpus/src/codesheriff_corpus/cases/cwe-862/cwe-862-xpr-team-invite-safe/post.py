@permission_required("team:manage")
def invite_member(self, team_id, email, role="member"):
    team = self.repo.get_team(team_id)
    invitation = Invitation.create(team=team, email=email, role=role)
    self.mailer.send_invitation(invitation)
    return invitation
