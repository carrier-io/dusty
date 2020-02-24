#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,E0401,W0702,W0703,R0902,R0914,R0915

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
    Scanner: Qualys WAS
"""

import os
import string
import random

from time import sleep, time
from datetime import datetime

from ruamel.yaml.comments import CommentedSeq
from ruamel.yaml.comments import CommentedMap

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.scanner import ScannerModel
from dusty.models.error import Error

from .helper import QualysHelper
from .parser import parse_findings


class Scanner(DependentModuleModel, ScannerModel):
    """ Scanner class """

    def __init__(self, context):
        """ Initialize scanner instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["scanners"][__name__.split(".")[-3]][__name__.split(".")[-2]]

    def execute(self):  # pylint: disable=R0912
        """ Run the scanner """
        helper = QualysHelper(
            self.context,
            self.config.get("qualys_api_server"),
            self.config.get("qualys_login"),
            self.config.get("qualys_password"),
            retries=self.config.get("retries", 10),
            retry_delay=self.config.get("retry_delay", 30.0),
            timeout=self.config.get("timeout", 120)
        )
        log.info("Qualys WAS version: %s", helper.get_version())
        timestamp = datetime.utcfromtimestamp(int(time())).strftime("%Y-%m-%d %H:%M:%S")
        sleep_interval = self.config.get("sleep_interval", 10.0)
        status_check_interval = self.config.get("status_check_interval", 60.0)
        # Create/get project
        project_name = "{}_{}".format(
            self.context.get_meta("project_name", "UnnamedProject"),
            self.context.get_meta("project_description", "Undescribed Project")
        )
        if self.config.get("random_name", False):
            project_name = f"{project_name}_{self.id_generator(8)}"
        log.info("Searching for existing webapp")
        webapp_id = helper.search_for_webapp(project_name)
        if webapp_id is None:
            log.info("Creating webapp")
            webapp_id = helper.create_webapp(
                project_name,
                self.config.get("target"),
                self.config.get("qualys_option_profile_id"),
                excludes=self.config.get("exclude", None)
            )
            sleep(sleep_interval)
        # Create auth record if needed
        auth_id = None
        if self.config.get("auth_script", None):
            log.info("Creating auth record")
            auth_name = f"{project_name} SeleniumAuthScript {timestamp}"
            auth_data = self.render_selenium_script(
                self.config.get("auth_script"),
                self.config.get("auth_login", ""),
                self.config.get("auth_password", ""),
                self.config.get("target")
            )
            auth_id = helper.create_selenium_auth_record(
                auth_name, auth_data,
                self.config.get("logged_in_indicator", "selenium")
            )
            sleep(sleep_interval)
            helper.add_auth_record_to_webapp(webapp_id, project_name, auth_id)
        # Start scan
        log.info("Starting scan")
        scan_name = f"{project_name} WAS {timestamp}"
        scan_auth = {"isDefault": True}
        if auth_id is not None:
            scan_auth = {"id": auth_id}
        scan_scanner = {"type": "EXTERNAL"}
        if self.config.get("qualys_scanner_type", "EXTERNAL") == "INTERNAL" and \
                self.config.get("qualys_scanner_pool", None):
            scanner_pool = self.config.get("qualys_scanner_pool")
            if isinstance(scanner_pool, str):
                scanner_pool = [item.strip() for item in scanner_pool.split(",")]
            scan_scanner = {
                "type": "INTERNAL",
                "friendlyName": random.choice(scanner_pool)
            }
        scan_id = helper.start_scan(
            scan_name, webapp_id,
            self.config.get("qualys_option_profile_id"),
            scan_scanner, scan_auth
        )
        sleep(sleep_interval)
        # Wait for scan to finish
        while helper.get_scan_status(scan_id) in ["SUBMITTED", "RUNNING"]:
            log.info("Waiting for scan to finish")
            sleep(status_check_interval)
        # Wait for results to finish processing
        if helper.get_scan_results_status(scan_id) == "UNKNOWN":
            log.warning(
                "Unable to find scan results status. Scan status: %s",
                helper.get_scan_status(scan_id)
            )
        while helper.get_scan_results_status(scan_id) in ["TO_BE_PROCESSED", "PROCESSING"]:
            log.info("Waiting for scan results to finish processing")
            sleep(status_check_interval)
        scan_result = helper.get_scan_results_status(scan_id)
        if scan_result in ["NO_HOST_ALIVE", "NO_WEB_SERVICE"]:
            error = Error(
                tool=self.get_name(),
                error=f"Qualys failed to access target",
                details="Qualys failed to access target " \
                        "(e.g. connection failed or target is not accessible). " \
                        "Please check scanner type/pool and target URL."
            )
            self.errors.append(error)
        if scan_result in ["SCAN_RESULTS_INVALID", "SERVICE_ERROR", "SCAN_INTERNAL_ERROR"]:
            error = Error(
                tool=self.get_name(),
                error=f"Qualys internal error occured",
                details="Qualys failed to perform scan (internal scan error occured). " \
                        "Please re-run the scan and check config if error persists."
            )
            self.errors.append(error)
        # Request report
        log.info("Requesting report")
        report_name = f"{project_name} WAS {timestamp} FOR Scan {scan_id}"
        report_id = helper.create_report(
            report_name, webapp_id,
            self.config.get("qualys_report_template_id")
        )
        sleep(sleep_interval)
        # Wait for report to be created
        while helper.get_report_status(report_id) in ["RUNNING"]:
            log.info("Waiting for report to be created")
            sleep(status_check_interval)
        # Download report
        log.info("Downloading report XML")
        report_xml = helper.download_report(report_id)
        # Delete assets
        log.info("Deleting assets")
        helper.delete_asset("report", report_id)
        helper.delete_asset("wasscan", scan_id)
        if auth_id is not None:
            helper.delete_asset("webappauthrecord", auth_id)
        helper.delete_asset("webapp", webapp_id)
        # Parse findings
        parse_findings(report_xml, self)
        # Save intermediates
        self.save_intermediates(report_xml)

    def save_intermediates(self, report_xml):
        """ Save scanner intermediates """
        if self.config.get("save_intermediates_to", None):
            log.info("Saving intermediates")
            base = os.path.join(self.config.get("save_intermediates_to"), __name__.split(".")[-2])
            try:
                # Make directory for artifacts
                os.makedirs(base, mode=0o755, exist_ok=True)
                # Save report
                with open(os.path.join(base, "report.xml"), "w") as report:
                    report.write(report_xml.decode("utf-8", errors="ignore"))
            except:
                log.exception("Failed to save intermediates")

    @staticmethod
    def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
        """ Generate random ID (legacy code) """
        return ''.join(random.choice(chars) for _ in range(size))

    @staticmethod
    def render_selenium_script(auth_script, auth_login, auth_password, target):
        """ Generate selenium script in HTML format """
        # pylint: disable=C0301
        result = \
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
            item_command = item["command"]
            item_target = item["target"]
            item_target = item_target.replace("%Target%", target)
            item_target = item_target.replace("%Username%", auth_login)
            item_target = item_target.replace("%Password%", auth_password)
            item_value = item["value"]
            item_value = item_value.replace("%Target%", target)
            item_value = item_value.replace("%Username%", auth_login)
            item_value = item_value.replace("%Password%", auth_password)
            result += \
                f'<tr>' \
                f'<td>{item_command}</td>' \
                f'<td>{item_target}</td>' \
                f'<td>{item_value}</td>' \
                f'</tr>'
        result += \
            f'</tbody></table>' \
            f'</body>' \
            f'</html>'
        return result

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj), "qualys_api_server", "https://qualysapi.qualys.eu",
            comment="Qualys API server URL"
        )
        data_obj.insert(
            len(data_obj), "qualys_login", "some-user",
            comment="Qualys user login"
        )
        data_obj.insert(
            len(data_obj), "qualys_password", "S0m3P@ssw0rd",
            comment="Qualys user password"
        )
        data_obj.insert(
            len(data_obj), "qualys_option_profile_id", 12345,
            comment="Qualys option profile ID"
        )
        data_obj.insert(
            len(data_obj), "qualys_report_template_id", 12345,
            comment="Qualys report template ID"
        )
        data_obj.insert(
            len(data_obj), "qualys_scanner_type", "EXTERNAL",
            comment="Qualys scanner type: EXTERNAL or INTERNAL"
        )
        data_obj.insert(
            len(data_obj), "qualys_scanner_pool", CommentedSeq(),
            comment="(INTERNAL only) Qualys scanner pool: list of scanner appliances to choose from"
        )
        pool_obj = data_obj["qualys_scanner_pool"]
        pool_obj.append("MY_SCANNER_Name1")
        pool_obj.append("MY_SCANNER_Name2")
        pool_obj.append("MY_OTHERSCANNER_Name")
        data_obj.insert(len(data_obj), "random_name", False, comment="Use random project name")
        data_obj.insert(len(data_obj), "target", "http://app:8080", comment="scan target")
        data_obj.insert(
            len(data_obj), "exclude", ["http://app:8080/logout.*"],
            comment="(optional) URLs regex to exclude from scan"
        )
        data_obj.insert(
            len(data_obj), "auth_login", "user",
            comment="(optional) User login for authenticated scan"
        )
        data_obj.insert(
            len(data_obj), "auth_password", "P@ssw0rd",
            comment="(optional) User password for authenticated scan"
        )
        data_obj.insert(
            len(data_obj), "auth_script", CommentedSeq(),
            comment="(optional) Selenium-like script for authenticated scan"
        )
        script_obj = data_obj["auth_script"]
        for command in [
                {"command": "open", "target": "%Target%/login", "value": ""},
                {"command": "waitForElementPresent", "target": "id=login_login", "value": ""},
                {"command": "waitForElementPresent", "target": "id=login_password", "value": ""},
                {"command": "waitForElementPresent", "target": "id=login_0", "value": ""},
                {"command": "type", "target": "id=login_login", "value": "%Username%"},
                {"command": "type", "target": "id=login_password", "value": "%Password%"},
                {"command": "clickAndWait", "target": "id=login_0", "value": ""}
        ]:
            command_obj = CommentedMap()
            command_obj.fa.set_flow_style()
            for key in ["command", "target", "value"]:
                command_obj.insert(len(command_obj), key, command[key])
            script_obj.append(command_obj)
        data_obj.insert(
            len(data_obj), "logged_in_indicator", "Logout",
            comment="(optional) Response regex that is always present for authenticated user"
        )
        data_obj.insert(
            len(data_obj), "sleep_interval", 10,
            comment="(optional) Seconds to sleep after creating new resource"
        )
        data_obj.insert(
            len(data_obj), "status_check_interval", 60,
            comment="(optional) Seconds to wait between scan/report status checks"
        )
        data_obj.insert(
            len(data_obj), "retries", 10,
            comment="(optional) API request retry count"
        )
        data_obj.insert(
            len(data_obj), "retry_delay", 30,
            comment="(optional) API request retry delay"
        )
        data_obj.insert(
            len(data_obj), "timeout", 120,
            comment="(optional) API request timeout"
        )
        data_obj.insert(
            len(data_obj), "save_intermediates_to", "/data/intermediates/dast",
            comment="(optional) Save scan intermediates (raw results, logs, ...)"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = [
            "qualys_api_server", "qualys_login", "qualys_password",
            "qualys_option_profile_id", "qualys_report_template_id",
            "qualys_scanner_type",
            "target"
        ]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def get_name():
        """ Module name """
        return "Qualys WAS"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "Qualys (R) Web Application Scanning"
