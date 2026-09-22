def delete_report(self, report_id):
    report = Report.query.get(report_id)
    assert_owner(report, current_user())
    report.delete()
    return report_id
