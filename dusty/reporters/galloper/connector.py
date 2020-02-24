from requests import post
from . import constants as c


class GalloperConnector(object):
    def __init__(self, url, login=None, password=None):
        self.url = url
        self.auth = None
        if login and password:
            self.auth = (login, password)

    def create_test_results(self, test_results):
        report_id = post(f'{self.url}{c.REPORT_API}', data=test_results, auth=self.auth,
                         headers = {"Content-type": "application/json"}).json()
        return report_id['id']

    def create_findings(self, findings):
        result = post(f'{self.url}{c.FINDING_API}', data=findings, auth=self.auth,
                      headers={"Content-type": "application/json"}).json()
        return result
