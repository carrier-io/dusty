from requests import post
import json
from . import constants as c


class ADOConnector(object):
    def __init__(self, organization, project, personal_access_token, issue_type, team=None):
        self.auth = ('', personal_access_token)
        self.project = f"{project}"
        self.team = f"{project}"
        if team:
            self.team = f"{project}\\{team}"
        issue_type = "task" if issue_type is None else issue_type
        self.url = c.CREATE_ISSUE_URL.format(organization=organization, project=project,
                                             type=issue_type, rules="false", notify="false")
        self.query_url = c.QUERY_ISSUE_URL.format(organization=organization, project=project)

    def create_finding(self, title, description=None, priority=None,
                       assignee=None, issue_hash=None, custom_fields=None, tags=None):
        if not custom_fields:
            custom_fields = dict()
        if tags:
            if '/fields/System.Tags' not in custom_fields:
                custom_fields['/fields/System.Tags'] = ""
            elif not custom_fields['/fields/System.Tags'].endswith(";"):
                custom_fields['/fields/System.Tags'] += ';'
            custom_fields['/fields/System.Tags'] += ";".join(tags)
        body = []
        fields_mapping = {
            "/fields/System.Title": title,
            "/fields/Microsoft.VSTS.Common.Priority": c.PRIORITY_MAPPING[priority],
            "/fields/System.Description": description,
            "/fields/System.AssignedTo": assignee,
            "/fields/System.AreaPath": self.team,
            "/fields/System.IterationPath": self.project
        }
        for key, value in {**fields_mapping, **custom_fields}.items():
            if value:
                _piece = {"op": "add", "path": key, "from": None, "value": value}
                body.append(_piece)
        if not self.search_for_issue(issue_hash):
            return post(self.url, auth=self.auth, json=body,
                        headers={'content-type': 'application/json-patch+json'})

        return {}

    def search_for_issue(self, issue_hash=None):
        q = f"SELECT [System.Id] From WorkItems Where [System.Description] Contains \"{issue_hash}\""
        data = post(self.query_url, auth=self.auth, json={"query": q},
                    headers={'content-type': 'application/json'}).json()
        if len(data["workItems"]):
            return True
        return False
