from dusty.data_model.canonical_model import DefaultModel


class PTAIModel(DefaultModel):
    def __init__(self, title, severity, description, tool, endpoints=None,
                 scanner_confidence=None, static_finding=None, dynamic_finding=None,
                 impact=None, mitigation=None, date=None, cwe=None, url=None,
                 steps_to_reproduce=None, severity_justification=None,
                 references=None, images=None, line_number=None,
                 sourcefilepath=None, sourcefile=None, param=None,
                 payload=None, line=None, file_path=None, comments=None,
                 **kwags):
        super().__init__(title, severity, description, tool, endpoints,
                 scanner_confidence, static_finding, dynamic_finding,
                 impact, mitigation, date, cwe, url,
                 steps_to_reproduce, severity_justification,
                 references, images, line_number,
                 sourcefilepath, sourcefile, param,
                 payload, line, file_path,
                 **kwags)
        self.finding['description'] = description
        self.finding['title'] = title
        self.finding['comments'] = comments
        self.scan_type = 'SAST'

    def __str__(self):
        return self.finding['description']

    def jira(self, jira_client, priority_mapping=None):
        issue, created = super().jira(jira_client, priority_mapping)
        if self.finding['comments']:
            for data in self.finding['comments']:
                jira_client.add_comment_to_issue(issue, data)
        return issue, created
