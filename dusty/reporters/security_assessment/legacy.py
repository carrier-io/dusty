import requests
from dusty.tools import log

class SecurityAssessmentApi:
    def __init__(self, config):
        self.config = config

    def scanner_finding(self, payload):
        activity_uuid = self.config.get("activity_id")
        url = f"{self.config.get('api_url')}/api/scanner-findings?activity_id={activity_uuid}"
        headers = {"Authorization": f"Bearer {self.config.get('bearer_token')}"}
        response = requests.post(
            url,
            json=payload,
            headers=headers
        )

        if response.status_code != 200:
            log.error(f"Reporting failed. Status: {response.status_code}. Content: {response.text}")
            return None
        log.info("Reporting successfully")
