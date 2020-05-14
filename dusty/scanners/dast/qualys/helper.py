#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,E0401,R0903,R0913,R0902

#   Copyright 2019 getcarrier.io
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""
    Qualys API helper
"""

import time
import requests
from dotted.utils import dot  # pylint: disable=C0411

from dusty.tools import log


class QualysHelper:
    """ Helps to query Qualys API """

    def __init__(self, context, server, login, password, retries=10, retry_delay=30.0, timeout=120):  # pylint: disable=R0913
        self.context = context
        self.server = server
        self.login = login
        self.password = password
        self.retries = retries
        self.retry_delay = retry_delay
        self.timeout = timeout
        self._connection_obj = None

    @property
    def _connection(self):
        """ Prepare connection object """
        if self._connection_obj is None:
            self._connection_obj = requests.Session()
            self._connection_obj.auth = (self.login, self.password)
            self._connection_obj.headers.update({"Accept": "application/json"})
        return self._connection_obj

    def _destroy_connection(self):
        """ Destroy connection object """
        if self._connection_obj is not None:
            self._connection_obj.close()
            self._connection_obj = None

    def _request(self, endpoint, json=None, validator=None):
        """ Perform API request (with error handling) """
        last_response_text = ""
        for retry in range(self.retries):
            try:
                response = self._request_raw(endpoint, json)
                if validator is not None and not validator(response):
                    last_response_text = response.text
                    raise ValueError(f"Invalid response: {response.text}")
                return response
            except:  # pylint: disable=W0702
                log.exception("Qualys API error [retry=%d]", retry)
                self._destroy_connection()
                time.sleep(self.retry_delay)
        raise RuntimeError(
            f"Qualys API request failed after {self.retries} retries. " \
            f"Last response: {last_response_text}"
        )

    def _request_raw(self, endpoint, json=None):
        """ Perform API request (directly) """
        api = self._connection
        if json is None:
            response = api.get(f"{self.server}{endpoint}", timeout=self.timeout)
        else:
            response = api.post(f"{self.server}{endpoint}", json=json, timeout=self.timeout)
        log.debug(
            "API response: %d [%s] %s",
            response.status_code, response.headers, response.text
        )
        return response

    def get_version(self):
        """ Get WAS version """
        response = self._request(
            "/qps/rest/portal/version",
            validator=lambda r: r.ok and \
                dot(r.json()).ServiceResponse.responseCode == "SUCCESS"
        )
        obj = dot(response.json())
        return obj.ServiceResponse.data[0]["Portal-Version"]["WAS-VERSION"]

    def search_for_webapp(self, webapp_name):
        """ Search for existing WebApp and get ID """
        response = self._request(
            "/qps/rest/3.0/search/was/webapp",
            json={
                "ServiceRequest": {
                    "filters": {
                        "Criteria": [{
                            "field": "name",
                            "operator": "EQUALS",
                            "value": webapp_name
                        }]
                    }
                }
            },
            validator=lambda r: r.ok and \
                dot(r.json()).ServiceResponse.responseCode == "SUCCESS"
        )
        obj = dot(response.json())
        if obj.ServiceResponse.count == 0:
            return None
        return obj.ServiceResponse.data[0].WebApp.id

    def count_scans_in_webapp(self, webapp_id):
        """ Count submitted/running scans in WebApp """
        response = self._request(
            "/qps/rest/3.0/count/was/wasscan",
            json={
                "ServiceRequest": {
                    "filters": {
                        "Criteria": [{
                            "field": "webApp.id",
                            "operator": "EQUALS",
                            "value": webapp_id
                        }, {
                            "field": "status",
                            "operator": "IN",
                            "value": "SUBMITTED,RUNNING"
                        }]
                    }
                }
            },
            validator=lambda r: r.ok and \
                dot(r.json()).ServiceResponse.responseCode == "SUCCESS"
        )
        obj = dot(response.json())
        try:
            return obj.ServiceResponse.count
        except:  # pylint: disable=W0702
            return 0  # On error - allow to try to delete stale project

    def create_webapp(self, name, application_url, option_profile, excludes=None):
        """ Create WebApp record """
        if excludes is None:
            payload = {
                "ServiceRequest": {
                    "data": {
                        "WebApp": {
                            "name": name,
                            "url": application_url,
                            "defaultProfile": {"id": int(option_profile)}
                        }
                    }
                }
            }
        else:
            payload = {
                "ServiceRequest": {
                    "data": {
                        "WebApp": {
                            "name": name,
                            "url": application_url,
                            "defaultProfile": {"id": int(option_profile)},
                            "urlBlacklist": {"set": {"UrlEntry": [
                                {"value": item, "regex": "true"} for item in excludes
                            ]}},
                            "postDataBlacklist": {"set": {"UrlEntry": [
                                {"value": item, "regex": "true"} for item in excludes
                            ]}}
                        }
                    }
                }
            }
        response = self._request(
            "/qps/rest/3.0/create/was/webapp", json=payload,
            validator=lambda r: r.ok and \
                dot(r.json()).ServiceResponse.responseCode == "SUCCESS"
        )
        obj = dot(response.json())
        return obj.ServiceResponse.data[0].WebApp.id

    def create_selenium_auth_record(self, name, script, regex):
        """ Create selenium auth record """
        response = self._request(
            "/qps/rest/3.0/create/was/webappauthrecord",
            json={
                "ServiceRequest": {
                    "data": {
                        "WebAppAuthRecord": {
                            "name": name,
                            "formRecord": {
                                "type": "SELENIUM",
                                "seleniumScript": {
                                    "name": "seleniumScriptOK",
                                    "data": script,
                                    "regex": regex
                                }
                            }
                        }
                    }
                }
            },
            validator=lambda r: r.ok and \
                dot(r.json()).ServiceResponse.responseCode == "SUCCESS"
        )
        obj = dot(response.json())
        return obj.ServiceResponse.data[0].WebAppAuthRecord.id

    def add_auth_record_to_webapp(self, webapp_id, webapp_name, auth_record_id):
        """ Add auth record to WebApp """
        response = self._request(
            f"/qps/rest/3.0/update/was/webapp/{webapp_id}",
            json={
                "ServiceRequest": {
                    "data": {
                        "WebApp": {
                            "name": webapp_name,
                            "authRecords": {
                                "add": {
                                    "WebAppAuthRecord": [{
                                        "id": auth_record_id
                                    }]
                                }
                            }
                        }
                    }
                }
            },
            validator=lambda r: r.ok and dot(r.json()).ServiceResponse.responseCode
        )
        obj = dot(response.json())
        return obj.ServiceResponse.responseCode == "SUCCESS"

    def delete_asset(self, asset_type, asset_id):
        """ Delete asset """
        response = self._request(
            f"/qps/rest/3.0/delete/was/{asset_type}/{asset_id}",
            json={}, validator=lambda r: r.ok and dot(r.json()).ServiceResponse.responseCode
        )
        obj = dot(response.json())
        return obj.ServiceResponse.responseCode == "SUCCESS"

    def start_scan(self, name, webapp_id, option_profile, scanner_appliance, auth_record):
        """ Start scan """
        response = self._request(
            "/qps/rest/3.0/launch/was/wasscan/",
            json={
                "ServiceRequest": {
                    "data": {
                        "WasScan": {
                            "name": name,
                            "type": "VULNERABILITY",
                            "target": {
                                "webApp": {"id": webapp_id},
                                "webAppAuthRecord": auth_record,
                                "scannerAppliance": scanner_appliance
                            },
                            "profile": {"id": int(option_profile)},
                            "sendMail": False
                        }
                    }
                }
            },
            validator=lambda r: r.ok and \
                dot(r.json()).ServiceResponse.responseCode == "SUCCESS"
        )
        obj = dot(response.json())
        return obj.ServiceResponse.data[0].WasScan.id

    def get_scan_status(self, scan_id):
        """ Get scan status """
        response = self._request(
            f"/qps/rest/3.0/status/was/wasscan/{scan_id}",
            validator=lambda r: r.ok and \
                dot(r.json()).ServiceResponse.responseCode == "SUCCESS"
        )
        obj = dot(response.json())
        return obj.ServiceResponse.data[0].WasScan.status

    def get_scan_results_status(self, scan_id):
        """ Get scan status """
        response = self._request(
            f"/qps/rest/3.0/status/was/wasscan/{scan_id}",
            validator=lambda r: r.ok and \
                dot(r.json()).ServiceResponse.responseCode == "SUCCESS"
        )
        obj = dot(response.json())
        try:
            return obj.ServiceResponse.data[0].WasScan.summary.resultsStatus
        except:  # pylint: disable=W0702
            return "UNKNOWN"

    def get_scan_summary(self, scan_id):
        """ Get scan summary """
        response = self._request(
            f"/qps/rest/3.0/status/was/wasscan/{scan_id}",
            validator=lambda r: r.ok and \
                dot(r.json()).ServiceResponse.responseCode == "SUCCESS"
        )
        obj = dot(response.json())
        try:
            return obj.ServiceResponse.data[0].WasScan.summary
        except:  # pylint: disable=W0702
            return dict()

    def create_report(self, name, webapp_id, report_template):
        """ Create report """
        response = self._request(
            "/qps/rest/3.0/create/was/report",
            json={
                "ServiceRequest": {
                    "data": {
                        "Report": {
                            "name": name,
                            "description": "Report generated by API with Dusty",
                            "format": "XML",
                            "type": "WAS_SCAN_REPORT",
                            "config": {
                                "webAppReport": {
                                    "target": {
                                        "webapps": {
                                            "WebApp": [{
                                                "id": webapp_id
                                            }]
                                        }
                                    }
                                }
                            },
                            "template": {"id": int(report_template)}
                        }
                    }
                }
            },
            validator=lambda r: r.ok and \
                dot(r.json()).ServiceResponse.responseCode == "SUCCESS"
        )
        obj = dot(response.json())
        return obj.ServiceResponse.data[0].Report.id

    def get_report_status(self, report_id):
        """ Get scan status """
        response = self._request(
            f"/qps/rest/3.0/status/was/report/{report_id}",
            validator=lambda r: r.ok and \
                dot(r.json()).ServiceResponse.responseCode == "SUCCESS"
        )
        obj = dot(response.json())
        return obj.ServiceResponse.data[0].Report.status

    def download_report(self, report_id):
        """ Download report data """
        response = self._request(
            f"/qps/rest/3.0/download/was/report/{report_id}",
            validator=lambda r: r.ok
        )
        return response.content
