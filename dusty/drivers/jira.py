import os
import logging
from copy import deepcopy
from jira import JIRA
from traceback import format_exc
from dusty import constants as const


class JiraWrapper(object):
    JIRA_REQUEST = 'project={} AND (description ~ "{}" OR labels in ({}))'

    def __init__(self, url, user, password, project, fields=None):
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
        self.fields = {}
        self.watchers = []
        if isinstance(fields, dict):
            if 'watchers' in fields.keys():
                self.watchers = [item.strip() for item in fields.pop('watchers').split(",")]
            all_jira_fields = self.client.fields()
            for key, value in fields.items():
                if value:
                    if isinstance(value, str) and const.JIRA_FIELD_DO_NOT_USE_VALUE in value:
                        continue
                    jira_keys = [item for item in all_jira_fields if item["id"] == key]
                    if not jira_keys:
                        jira_keys = [item for item in all_jira_fields
                                     if item["name"].lower() == key.lower().replace('_', ' ')]
                    if len(jira_keys) == 1:
                        jira_key = jira_keys[0]
                        key_type = jira_key['schema']['type']
                    else:
                        logging.warning(f'Cannot recognize field {key}. This field will not be used.')
                        continue
                    if key_type in ['string', 'number', 'any'] or isinstance(value, dict):
                        _value = value
                    elif key_type == 'array':
                        if isinstance(value, str):
                            _value = [item.strip() for item in value.split(",")]
                        elif isinstance(value, int):
                            _value = [value]
                    else:
                        _value = {'name': value}
                    self.fields[jira_key['id']] = _value
        if not self.fields.get('issuetype', None):
            self.fields['issuetype'] = {'name': '!default_issuetype'}
        self.client.close()
        self.created_jira_tickets = list()

    def connect(self):
        self.client = JIRA(self.url, basic_auth=(self.user, self.password))

    def markdown_to_jira_markdown(self, content):
        return content.replace("###", "h3.").replace("**", "*")

    def create_issue(self, title, priority, description, issue_hash, attachments=None, get_or_create=True,
                     additional_labels=None):

        def replace_defaults(value):
            if isinstance(value, str) and const.JIRA_FIELD_USE_DEFAULT_VALUE in value:
                for default_key in default_fields.keys():
                    if default_key in value:
                        value = value.replace(default_key, default_fields[default_key])
            return value

        default_fields = {
            '!default_issuetype': 'Bug',
            '!default_summary': title,
            '!default_description': description,
            '!default_priority': priority}
        description = self.markdown_to_jira_markdown(description)
        issue_data = {
            'project': {'key': self.project},
            'issuetype': 'Bug',
            'summary': title,
            'description': description,
            'priority': {'name': priority}
        }
        fields = deepcopy(self.fields)
        for key, value in fields.items():
            if isinstance(value, str):
                if const.JIRA_FIELD_DO_NOT_USE_VALUE in value:
                    issue_data.pop(key)
                else:
                    issue_data[key] = replace_defaults(value)
            elif isinstance(value, list):
                for item in value:
                    value[value.index(item)] = replace_defaults(item)
                if issue_data.get(key):
                    issue_data[key].extend(value)
                else:
                    issue_data[key] = value
            elif isinstance(value, dict):
                for _key, _value in value.items():
                    value[_key] = replace_defaults(_value)
                issue_data[key] = value
            elif not key in issue_data:
                issue_data[key] = value
            else:
                logging.warning('field {} is already set and has \'{}\' value'.format(key, issue_data[key]))
        _labels = []
        if additional_labels and isinstance(additional_labels, list):
            _labels.extend(additional_labels)
        if issue_data.get('labels', None):
            issue_data['labels'].extend(_labels)
        else:
            issue_data['labels'] = _labels
        jira_request = self.JIRA_REQUEST.format(issue_data["project"]["key"], issue_hash, issue_hash)
        if get_or_create:
            issue, created = self.get_or_create_issue(jira_request, issue_data)
        else:
            issue = self.post_issue(issue_data)
            created = True
        try:
            if attachments:
                for attachment in attachments:
                    if 'binary_content' in attachment:
                        self.add_attachment(issue.key,
                                            attachment=attachment['binary_content'],
                                            filename=attachment['message'])
            for watcher in self.watchers:
                self.client.add_watcher(issue.id, watcher)
        except:
            if os.environ.get("debug", False):
                logging.error(format_exc())
        finally:
            self.created_jira_tickets.append({'description': issue.fields.summary,
                                              'priority': issue.fields.priority,
                                              'key': issue.key,
                                              'link': self.url + '/browse/' + issue.key,
                                              'new': created,
                                              'assignee': issue.fields.assignee,
                                              'status': issue.fields.status.name,
                                              'open_date': issue.fields.created})
        return issue, created

    def add_attachment(self, issue_key, attachment, filename=None):
        issue = self.client.issue(issue_key)
        for _ in issue.fields.attachment:
            if _.filename == filename:
                return
        self.client.add_attachment(issue, attachment, filename)

    def post_issue(self, issue_data):
        issue = self.client.create_issue(fields=issue_data)
        logging.info(f'  \u2713 {issue_data["issuetype"]["name"]} was created: {issue.key}')
        return issue

    def get_or_create_issue(self, search_string, issue_data):
        issuetype = issue_data['issuetype']
        created = False
        jira_results = self.client.search_issues(search_string)
        issues = []
        for each in jira_results:
            if each.fields.summary == issue_data.get('summary', None):
                issues.append(each)
        if len(issues) == 1:
            issue = issues[0]
            if len(issues) > 1:
                logging.error('  more then 1 issue with the same summary')
            else:
                logging.info(f'  {issuetype["name"]} already exists: {issue.key}')
        else:
            issue = self.post_issue(issue_data)
            created = True
        return issue, created

    def add_comment_to_issue(self, issue, data):
        return self.client.add_comment(issue, data)

    def get_created_tickets(self):
        return self.created_jira_tickets


