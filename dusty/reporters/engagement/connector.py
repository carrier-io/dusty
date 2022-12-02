from requests import post
from json import dumps

from . import constants as c

class IssuesConnector(object):
    def __init__(self, url, token, project_id):
        self.url = url
        self.token = token
        self.issues_api = c.ISSUES_API.format(project_id)
        self.headers = {
            "Content-type": "application/json",
            "Authorization": f"Bearer {token}",
        }

    def create_issues(self, findings):
        result = post(f'{self.url}{self.issues_api}',
                      data=dumps(findings),
                      headers=self.headers)
        return result.content
