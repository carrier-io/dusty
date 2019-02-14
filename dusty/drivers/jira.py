import logging
from jira import JIRA


class JiraWrapper(object):
    JIRA_REQUEST = 'project={} AND labels in ({})'

    def __init__(self, url, user, password, project, assignee, issue_type='Bug', labels=None, watchers=None,
                 jira_epic_key=None, fields=None):
        self.valid = True
        self.url = url
        self.password = password
        self.user = user
        try:
            self.connect()
        except:
            self.valid = False
            return
        self.projects = [project.key for project in self.client.projects()]
        self.project = project.upper()
        if self.project not in self.projects:
            self.client.close()
            self.valid = False
            return
        self.assignee = assignee
        self.issue_type = issue_type
        self.labels = list()
        if labels:
            self.labels = [label.strip() for label in labels.split(",")]
        self.watchers = list()
        if watchers:
            self.watchers = [watchers.strip() for watchers in watchers.split(",")]
        self.jira_epic_key = jira_epic_key
        self.fields = {}
        if fields and isinstance(fields, dict):
            self.fields = fields
        self.client.close()
        self.created_jira_tickets = list()

    def connect(self):
        self.client = JIRA(self.url, basic_auth=(self.user, self.password))

    def markdown_to_jira_markdown(self, content):
        return content.replace("###", "h3.").replace("**", "*")

    def create_issue(self, title, priority, description, issue_hash, attachments=None, get_or_create=True,
                     additional_labels=None):
        description = self.markdown_to_jira_markdown(description)
        _labels = [issue_hash]
        if additional_labels and isinstance(additional_labels, list):
            _labels.extend(additional_labels)
        _labels.extend(self.labels)
        issue_data = {
            'project': {'key': self.project},
            'summary': title,
            'description': description,
            'issuetype': {'name': self.issue_type},
            'assignee': {'name': self.assignee},
            'priority': {'name': priority},
            'labels': _labels
        }
        for key, value in self.fields.items():
            if not key in issue_data:
                issue_data[key] = value
            else:
                print('field {} is already set and has \'{}\' value'.format(key, issue_data[key]))
        jira_request = self.JIRA_REQUEST.format(issue_data["project"]["key"], issue_hash)
        if get_or_create:
            issue, created = self.get_or_create_issue(jira_request, issue_data)
        else:
            issue = self.post_issue(issue_data)
            created = True
        if attachments:
            for attachment in attachments:
                if 'binary_content' in attachment:
                    self.add_attachment(issue.key,
                                        attachment=attachment['binary_content'],
                                        filename=attachment['message'])
        for watcher in self.watchers:
            self.client.add_watcher(issue.id, watcher)
        if self.jira_epic_key:
            self.client.add_issues_to_epic(self.jira_epic_key, [issue.id])
        self.created_jira_tickets.append({'description': issue.fields.summary,
                                              'priority': issue.fields.priority,
                                              'key': issue.key,
                                              'link': self.url + '/browse/' + issue.key,
                                              'new': created,
                                              'assignee': issue.fields.assignee,
                                              'status': issue.fields.status.name,
                                              'open_date': issue.fields.created
                                              })
        return issue, created

    def add_attachment(self, issue_key, attachment, filename=None):
        issue = self.client.issue(issue_key)
        for _ in issue.fields.attachment:
            if _.filename == filename:
                return
        self.client.add_attachment(issue, attachment, filename)

    def post_issue(self, issue_data):
        issue = self.client.create_issue(fields=issue_data)
        logging.info(f'  \u2713 {issue_data["issuetype"]["name"]} issue was created: {issue.key}')
        return issue

    def get_or_create_issue(self, search_string, issue_data):
        issuetype = issue_data['issuetype']['name']
        created = False
        jira_results = self.client.search_issues(search_string)
        issues = []
        for each in jira_results:
            if each.fields.summary == issue_data.get('summary', None):
                issues.append(each)
        if len(issues) == 1:
            issue = issues[0]
            if len(issues) > 1:
                print('  more then 1 issue with the same summary')
            else:
                print(f'  {issuetype} issue already exists: {issue.key}')
        else:
            issue = self.post_issue(issue_data)
            created = True
        return issue, created

    def add_comment_to_issue(self, issue, data):
        return self.client.add_comment(issue, data)

    def get_created_tickets(self):
        return self.created_jira_tickets


