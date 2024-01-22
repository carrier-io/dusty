import os
from requests import post
from json import dumps
from . import constants as c


class CentryConnector(object):
    def __init__(self, url, token, project_id, test_id, test_type):
        self.url = url
        self.project_id = project_id
        self.test_id = test_id
        self.test_type = test_type
        #
        test_plugin = c.TEST_MAPPING[test_type]

        self.report_url = c.REPORT_API.format(project_id=self.project_id, test_id=self.test_id, test_plugin=test_plugin)
        self.finding_api = c.FINDING_API.format(project_id=self.project_id, test_id=self.test_id, test_plugin=test_plugin)
        #
        self.headers = {
            "Content-type": "application/json",
            "Authorization": f"Bearer {token}",
        }

    def create_test_results(self, test_results):
        report_id = post(f'{self.url}{self.report_url}',
                         data=dumps(test_results),
                         headers=self.headers,
                         verify=os.environ.get("SSL_VERIFY", "").lower() in ["true", "yes"],
                         timeout=120.0).json()
        return report_id['id']

    def create_findings(self, findings):
        result = post(f'{self.url}{self.finding_api}',
                      data=dumps(findings),
                      headers=self.headers,
                      verify=os.environ.get("SSL_VERIFY", "").lower() in ["true", "yes"],
                      timeout=120.0)
        return result.content
