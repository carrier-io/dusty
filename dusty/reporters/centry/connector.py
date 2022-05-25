from requests import post
from json import dumps
from . import constants as c


class CentryConnector(object):
    def __init__(self, url, token, project_id, test_id):
        self.url = url
        self.project_id = project_id
        self.test_id = test_id
        #
        self.report_url = c.REPORT_API.format(project_id=self.project_id, test_id=self.test_id)
        self.finding_api = c.FINDING_API.format(project_id=self.project_id, test_id=self.test_id)
        #
        self.headers = {
            "Content-type": "application/json",
            "Authorization": f"Bearer {token}",
        }

    def create_test_results(self, test_results):
        report_id = post(f'{self.url}{self.report_url}',
                         data=dumps(test_results),
                         headers=self.headers).json()
        return report_id['id']

    def create_findings(self, findings):
        result = post(f'{self.url}{self.finding_api}',
                      data=dumps(findings),
                      headers=self.headers)
        return result.content
