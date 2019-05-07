#   Copyright 2018 getcarrier.io
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

import os
import logging
from os import environ
from traceback import format_exc

import qualysapi.connector as qcconn
from lxml import objectify
from dusty import constants as c


class WAS(object):
    def __init__(self):
        self.client = qcconn.QGConnector((environ.get('QUALYS_LOGIN'), environ.get('QUALYS_PASSWORD')),
                                         environ.get('QUALYS_API_SERVER'), None, 5)
        self.status_check_errors = 0

    def search_for_project(self, project_name):
        call = '/search/was/webapp'
        body = f'<ServiceRequest><filters>' \
               f'<Criteria field="name" operator="EQUALS">{project_name}</Criteria>' \
               f'</filters></ServiceRequest>'
        response = self.client.request(call, data=body, api_version='webapp')
        logging.debug("Qualys: API response: %s", str(response))
        root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
        return None if int(root.count.text) == 0 else root.data.WebApp.id.text

    def count_scans_in_project(self, project_id):
        try:
            call = '/search/was/wasscan'
            body = f'<ServiceRequest><filters>' \
                   f'<Criteria field="webApp.id" operator="EQUALS">{project_id}</Criteria>' \
                   f'<Criteria field="status" operator="IN">SUBMITTED,RUNNING</Criteria>' \
                   f'</filters></ServiceRequest>'
            response = self.client.request(call, data=body, api_version='webapp')
            logging.debug("Qualys: API response: %s", str(response))
            root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
            return int(root.count.text)
        except:
            return 0  # On error - allow to try to delete stale project

    def create_webapp_request(self, project_name, application_url, scan_profile, excludes=None):
        call = '/create/was/webapp'
        body = f'<ServiceRequest><data><WebApp>' \
               f'<name>{project_name}</name>' \
               f'<url>{application_url}</url>' \
               f'<defaultProfile><id>{scan_profile}</id></defaultProfile>'
        if excludes:
            body += f'<urlBlacklist><set>'
            for item in excludes:
                body += f'<UrlEntry regex="true"><![CDATA[{item}]]></UrlEntry>'
            body += f'</set></urlBlacklist>'
            body += f'<postDataBlacklist><set>'
            for item in excludes:
                body += f'<UrlEntry regex="true"><![CDATA[{item}]]></UrlEntry>'
            body += f'</set></postDataBlacklist>'
        body += f'</WebApp></data></ServiceRequest>'
        response = self.client.request(call, data=body, api_version="webapp")
        logging.debug("Qualys: API response: %s", str(response))
        root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
        return None if root.responseCode.text != 'SUCCESS' else root.data.WebApp.id.text

    def add_auth_record(self, project_id, project_name, auth_id):
        call = f'/update/was/webapp/{project_id}'
        body = f'<ServiceRequest><data><WebApp>' \
               f'<name>{project_name}</name>' \
               f'<authRecords><add><WebAppAuthRecord>' \
               f'<id>{auth_id}</id>' \
               f'</WebAppAuthRecord></add></authRecords>' \
               f'</WebApp></data></ServiceRequest>'
        response = self.client.request(call, data=body, api_version="webapp")
        logging.debug("Qualys: API response: %s", str(response))
        root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
        if root.responseCode.text != 'SUCCESS':
            raise RuntimeError(f"Failed to add auth record")
        return root.responseCode.text == 'SUCCESS'

    def create_auth_record(self, project_name, ts, auth_script, auth_login, auth_password):
        call = '/create/was/webappauthrecord'
        body = f'<ServiceRequest><data><WebAppAuthRecord>' \
               f'<name>{project_name} SeleniumAuthScript {ts}</name>' \
               f'<formRecord><type>SELENIUM</type><seleniumScript>' \
               f'<name>seleniumScriptOK</name>' \
               f'<data><![CDATA[' \
               f'<?xml version="1.0" encoding="UTF-8"?>' \
               f'<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">' \
               f'<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">' \
               f'<head profile="http://selenium-ide.openqa.org/profiles/test-case">' \
               f'<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />' \
               f'<link rel="selenium.base" href="https://community.qualys.com/" />' \
               f'<title>seleniumScriptOK</title>' \
               f'</head>' \
               f'<body>' \
               f'<table cellpadding="1" cellspacing="1" border="1">' \
               f'<thead>' \
               f'<tr><td rowspan="1" colspan="3">seleniumScriptOK</td></tr>' \
               f'</thead><tbody>'
        for item in auth_script:
            item_value = item["value"]
            item_value = item_value.replace("%Username%", auth_login)
            item_value = item_value.replace("%Password%", auth_password)
            body += f'<tr>' \
                    f'<td>{item["command"]}</td>' \
                    f'<td>{item["target"]}</td>' \
                    f'<td>{item_value}</td>' \
                    f'</tr>'
        body += f'</tbody></table>' \
               f'</body>' \
               f'</html>' \
               f']]></data>' \
               f'<regex>selenium</regex>' \
               f'</seleniumScript></formRecord>' \
               f'</WebAppAuthRecord></data></ServiceRequest>'
        response = self.client.request(call, data=body, api_version="webapp")
        logging.debug("Qualys: API response: %s", str(response))
        root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
        return None if root.responseCode.text != 'SUCCESS' else root.data.WebAppAuthRecord.id.text

    def start_scan(self, project_name, ts,  project_id, scan_profile, scanner_appliance="EXTERNAL", auth_record_id=None):
        if scanner_appliance == 'EXTERNAL':
            scanner_appliance = "<type>EXTERNAL</type>"
        auth_record = "<isDefault>true</isDefault>"
        if auth_record_id:
            auth_record = f"<id>{auth_record_id}</id>"
        call = '/launch/was/wasscan'
        body = f'<ServiceRequest><data>' \
               f'<WasScan>' \
               f'<name>{project_name} WAS {ts}</name>' \
               f'<type>VULNERABILITY</type>' \
               f'<target>' \
               f'<webApp><id>{project_id}</id></webApp>' \
               f'<webAppAuthRecord>{auth_record}</webAppAuthRecord>' \
               f'<scannerAppliance>' \
               f'{scanner_appliance}' \
               f'</scannerAppliance>' \
               f'</target>' \
               f'<profile>' \
               f'<id>{scan_profile}</id>' \
               f'</profile>' \
               f'<sendMail>false</sendMail>' \
               f'</WasScan>' \
               f'</data></ServiceRequest>'
        response = self.client.request(call, data=body, api_version="webapp")
        logging.debug("Qualys: API response: %s", str(response))
        root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
        return None if root.responseCode.text != 'SUCCESS' else root.data.WasScan.id.text

    def scan_status(self, scan_id):
        logging.info("Qualys: checking scan status")
        try:
            call = f'/get/was/wasscan/{scan_id}'
            response = self.client.request(call, api_version="webapp")
            logging.debug("Qualys: API response: %s", str(response))
            root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
            if root.responseCode.text != 'SUCCESS':
                raise RuntimeError(f"Qualys API error")
        except:
            logging.error("Failed to get scan status. Total status errors: %d", self.status_check_errors)
            if os.environ.get("debug", False):
                logging.error(format_exc())
            if self.status_check_errors > c.QUALYS_MAX_STATUS_CHECK_ERRORS:
                raise
            self.status_check_errors += 1
            return False
        if root.data.WasScan.status in ["CANCELED", "ERROR"]:
            raise RuntimeError("QualysWAS scan failed or was canceled")
        if root.data.WasScan.status == "FINISHED" and \
                root.data.WasScan.summary.resultsStatus in ["NO_WEB_SERVICE", "NO_HOST_ALIVE"]:
            raise RuntimeError("QualysWAS failed to access web application")
        return root.data.WasScan.status == "FINISHED"

    def download_scan_report(self, scan_id, report_path='/tmp/qualys_scan.xml'):
        call = f'/download/was/wasscan/{scan_id}'
        response = self.client.request(call, api_version="webapp")
        with open(report_path, 'w') as f:
            f.write(response)
        return True

    def request_report(self, project_name, ts, scan_id, project_id, qualys_template_id):
        call = '/create/was/report'
        # f'<scans><WasScan><id>{scan_id}</id></WasScan></scans>' \
        body = f'<?xml version="1.0" encoding="UTF-8"?><ServiceRequest><data>' \
               f'<Report><name>{project_name} WAS {ts} FOR Scan {scan_id}</name>' \
               f'<description>Report generated by API with Dusty</description>' \
               f'<format>XML</format>' \
               f'<type>WAS_SCAN_REPORT</type>' \
               f'<config><webAppReport><target>' \
               f'<webapps><WebApp><id>{project_id}</id></WebApp></webapps>' \
               f'</target></webAppReport></config>' \
               f'<template><id>{qualys_template_id}</id></template></Report></data></ServiceRequest>'
        response = self.client.request(call, data=body, api_version="webapp")
        logging.debug("Qualys: API response: %s", str(response))
        root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
        return None if root.responseCode.text != 'SUCCESS' else root.data.Report.id

    def get_report_status(self, report_id):
        logging.info("Qualys: checking report status")
        try:
            call = f'/get/was/report/{report_id}'
            response = self.client.request(call, api_version="webapp")
            logging.debug("Qualys: API response: %s", str(response))
            root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
            if root.responseCode.text != 'SUCCESS':
                raise RuntimeError(f"Qualys API error")
        except:
            logging.error("Failed to get report status. Total status errors: %d", self.status_check_errors)
            if os.environ.get("debug", False):
                logging.error(format_exc())
            if self.status_check_errors > c.QUALYS_MAX_STATUS_CHECK_ERRORS:
                raise
            self.status_check_errors += 1
            return False
        return root.data.Report.status == "COMPLETE"

    def download_report(self, report_id, report_path='/tmp/qualys.xml'):
        call = f'/download/was/report/{report_id}'
        response = self.client.request(call, api_version="webapp")
        with open(report_path, 'w') as f:
            f.write(response)
        return True

    def delete_asset(self, asset_type, asset_id):
        call = f'/delete/was/{asset_type}/{asset_id}'
        response = self.client.request(call, api_version="webapp")
        logging.debug("Qualys: API response: %s", str(response))
        root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
        return root.responseCode.text != 'SUCCESS'
