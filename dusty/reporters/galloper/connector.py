from requests import post
from json import dumps
from . import constants as c


class GalloperConnector(object):
    def __init__(self, url, project_id=None, login=None, password=None, token=None):
        self.url = url
        self.auth = None
        self.project_id = project_id
        self.report_url = c.LEGACY_API
        self.finding_api = c.LEGACY_FINDING_API
        if project_id:
            self.report_url = c.REPORT_API.format(project_id=self.project_id)
            self.finding_api = c.FINDING_API.format(project_id=self.project_id)
        self.headers = {"Content-type": "application/json"}
        if login and password:
            self.auth = (login, password)
        if token:
            self.headers["Authorization"] = f"bearer {token}"

    def create_test_results(self, test_results):
        report_id = post(f'{self.url}{self.report_url}',
                         data=dumps(test_results), auth=self.auth,
                         headers=self.headers).json()
        return report_id['id']

    def create_findings(self, findings):
        result = post(f'{self.url}{self.finding_api}',
                      data=dumps(findings), auth=self.auth,
                      headers=self.headers).json()
        return result
