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

import logging
from os import environ

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
        if environ.get("debug", False):
            print(response)
        root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
        return None if int(root.count.text) == 0 else root.data.WebApp.id.text

    def create_webapp_request(self, project_name, application_url, scan_profile):
        call = '/create/was/webapp'
        body = f'<ServiceRequest><data><WebApp>' \
               f'<name>{project_name}</name>' \
               f'<url>{application_url}</url>' \
               f'<defaultProfile><id>{scan_profile}</id></defaultProfile>' \
               f'</WebApp></data></ServiceRequest>'
        response = self.client.request(call, data=body, api_version="webapp")
        if environ.get("debug", False):
            print(response)
        root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
        return None if root.responseCode.text != 'SUCCESS' else root.data.WebApp.id.text

    def start_scan(self, project_name, ts,  project_id, scan_profile, scanner_appliance="EXTERNAL"):
        if scanner_appliance == 'EXTERNAL':
            scanner_appliance = "<type>EXTERNAL</type>"
        call = '/launch/was/wasscan'
        body = f'<ServiceRequest><data>' \
               f'<WasScan>' \
               f'<name>{project_name} WAS {ts}</name>' \
               f'<type>VULNERABILITY</type>' \
               f'<target>' \
               f'<webApp><id>{project_id}</id></webApp>' \
               f'<webAppAuthRecord><isDefault>true</isDefault></webAppAuthRecord>' \
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
        if environ.get("debug", False):
            print(response)
        root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
        return None if root.responseCode.text != 'SUCCESS' else root.data.WasScan.id.text

    def scan_status(self, scan_id):
        try:
            call = f'/get/was/wasscan/{scan_id}'
            response = self.client.request(call, api_version="webapp")
            if environ.get("debug", False):
                print(response)
            root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
            if root.responseCode.text == 'SUCCESS':
                return False if root.data.WasScan.status != "FINISHED" else True
            return False
        except:
            logging.error("Failed to get scan status. Total status errors: %d", self.status_check_errors)
            if self.status_check_errors > c.QUALYS_MAX_STATUS_CHECK_ERRORS:
                raise
            self.status_check_errors += 1
            return False

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
        if environ.get("debug", False):
            print(response)
        root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
        return None if root.responseCode.text != 'SUCCESS' else root.data.Report.id

    def get_report_status(self, report_id):
        try:
            call = f'/get/was/report/{report_id}'
            response = self.client.request(call, api_version="webapp")
            if environ.get("debug", False):
                print(response)
            root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
            if root.responseCode.text == 'SUCCESS':
                return False if root.data.Report.status != "COMPLETE" else True
            return False
        except:
            logging.error("Failed to get report status. Total status errors: %d", self.status_check_errors)
            if self.status_check_errors > c.QUALYS_MAX_STATUS_CHECK_ERRORS:
                raise
            self.status_check_errors += 1
            return False

    def download_report(self, report_id, report_path='/tmp/qualys.xml'):
        call = f'/download/was/report/{report_id}'
        response = self.client.request(call, api_version="webapp")
        with open(report_path, 'w') as f:
            f.write(response)
        return True

    def delete_asset(self, asset_type, asset_id):
        call = f'/delete/was/{asset_type}/{asset_id}'
        response = self.client.request(call, api_version="webapp")
        if environ.get("debug", False):
            print(response)
        root = objectify.fromstring(response.encode("utf-8", errors="ignore"))
        return True if root.responseCode.text != 'SUCCESS' else False
