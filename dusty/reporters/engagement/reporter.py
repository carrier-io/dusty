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
    Reporter: Engagement
"""

import hashlib
from dusty.tools import markdown, log
from dusty.models.module import DependentModuleModel
from dusty.models.reporter import ReporterModel
from dusty.constants import SEVERITIES
from . import connector


class Reporter(DependentModuleModel, ReporterModel):
    """ Report findings from scanners """

    def __init__(self, context):
        """ Initialize reporter instance """
        super().__init__()
        self.context = context
        self.report_id = context.config['reporters']['centry']['test_id']
        self.target = list(context.config['scanners']['dast'].values())[0]['target']
        self.config = \
            self.context.config["reporters"][__name__.split(".")[-2]]
        self.issues_connector = connector.IssuesConnector(
            self.config['url'],
            self.config['token'],
            self.config['project_id']
        )

    def report(self):
        """ Report """
        issues = []
        for finding in self.context.findings:
            title = self.get_title(finding.title)
            issue = {
                'issue_id': self.get_hash_code(title),
                'title': title,
                "description": markdown.markdown_to_html(finding.description),
                "severity": finding.get_meta("severity", SEVERITIES[-1]),
                "project": None,
                "asset": None,
                "type": "Vulnerability",
                "engagement": self.config['engagement_id'],
                "source_type": "security",
                "report_id": self.report_id,
            }
            issues.append(issue)
        self.issues_connector.create_issues(issues)

    def get_hash_code(self, title):
        return hashlib.sha256(title.strip().encode('utf-8')).hexdigest()

    def get_title(self, title):
        return f"{title}. DAST SCAN: {self.target}"

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(len(data_obj), "url", "http://CENTRY_URL", comment="REST API for reporting")
        data_obj.insert(len(data_obj), "project_id", "1", comment="ID of project to report to")
        data_obj.insert(len(data_obj), "token", "", comment="Token for authentication")
        data_obj.insert(len(data_obj), "engagement_id", "", comment="Engagement id under which tests being executed")


    @staticmethod
    def get_name():
        """ Reporter name """
        return "Engagement"

    @staticmethod
    def get_description():
        """ Reporter description """
        return "Reports findings to issues endpoint"
