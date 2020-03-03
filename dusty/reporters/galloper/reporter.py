#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,E0401

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
    Reporter: Galloper
"""


from dusty.tools import markdown, log
from dusty.models.module import DependentModuleModel
from dusty.models.reporter import ReporterModel
from dusty.models.finding import DastFinding, SastFinding
from dusty.constants import SEVERITIES

from . import connector


class Reporter(DependentModuleModel, ReporterModel):
    """ Report findings from scanners """

    def __init__(self, context):
        """ Initialize reporter instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["reporters"][__name__.split(".")[-2]]
        self.galloper = connector.GalloperConnector(self.config['url'],
                                                    self.config.get('login'),
                                                    self.config.get('password'))

    def report(self):
        """ Report """
        # Summary
        test_initiation_body = {
            "project_name": self.context.get_meta('project_name'),
            "app_name": self.context.get_meta("project_description"),
            "scan_time": self.context.performers["reporting"].get_module_meta("time_meta", "testing_run_time", None),
            "dast_target": self.context.get_meta("dast_target"),
            "sast_code": self.context.get_meta("sast_code"),
            "scan_type": self.context.get_meta("testing_type"),
            "findings": len(self.context.findings),
            "false_positives": 0,
            "excluded": 0,
            "info_findings": 0,
            "environment": self.context.get_meta("environment_name")
        }
        false_positives = 0
        excluded = 0
        info_findings = 0
        for item in self.context.findings:
            if item.get_meta("false_positive_finding", False):
                false_positives += 1
            if item.get_meta("information_finding", False):
                info_findings += 1
            if item.get_meta("excluded_finding", False):
                excluded += 1
        test_initiation_body['false_positives'] = false_positives
        test_initiation_body['info_findings'] = info_findings
        test_initiation_body['excluded_finding'] = excluded
        report_id = self.galloper.create_test_results(test_initiation_body)
        test_cases = list()
        for item in self.context.findings:
            issue = {
                "report_id": report_id,
                "issue_hash": item.get_meta("issue_hash", ""),
                "tool_name": item.get_meta("tool", ""),
                "description": item.title,
                "severity": item.get_meta("severity", SEVERITIES[-1]),
                "details": '',
                "endpoints": item.get_meta("endpoints"),
                "false_positive": 0 if not item.get_meta("false_positive_finding", False) else 1,
                "info_finding": 0 if not item.get_meta("information_finding", False) else 1,
                "excluded_finding": 0 if not item.get_meta("excluded_finding", False) else 1
            }
            if isinstance(item, DastFinding):
                issue['details'] = markdown.markdown_to_html(item.description)
            elif isinstance(item, SastFinding):
                issue['details'] = markdown.markdown_to_html("\n\n".join(item.description))
            test_cases.append(issue)
        log.info("Creating findings")
        self.galloper.create_findings(test_cases)

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(len(data_obj), "url", "http://GALLOPER_URL", comment="REST API for reporting")
        data_obj.insert(len(data_obj), "login", "", comment="Login to REST API")
        data_obj.insert(len(data_obj), "password", "", comment="Password to REST API")

    @staticmethod
    def get_name():
        """ Reporter name """
        return "Galloper"

    @staticmethod
    def get_description():
        """ Reporter description """
        return "Galloper REST API reporter"
