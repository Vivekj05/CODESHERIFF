def share_report(self, report_id, recipient_email):
    report = Report.query.get(report_id)
    link = self.links.create(report, recipient_email)
    self.mailer.send_share_link(recipient_email, link)
    return link
