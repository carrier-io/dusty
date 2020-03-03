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
        organization = self.config["org"],
        project = self.config["project"],
        personal_access_token = self.config["pat"]
        team = self.config.get("team", None)
        issue_type = self.config.get("issue_type", "task")
        self.other_fields = self.config.get("custom_fields", {})
        self.assignee = self.config.get("assignee", None)
        self.ado = connector.ADOConnector(organization, project, personal_access_token, team, issue_type)

    def report(self):
        """ Report """
        # Summary
        for item in self.context.findings:
            if not (item.get_meta("false_positive_finding", False) and item.get_meta("information_finding", False) and
                    item.get_meta("excluded_finding", False)):
                continue
            details = ''
            if isinstance(item, DastFinding):
                details = markdown.markdown_to_text(item.description)
            elif isinstance(item, SastFinding):
                details = markdown.markdown_to_text("\n\n".join(item.description))
            log.debug(self.ado.create_finding(item.title, details, item.get_meta("severity", SEVERITIES[-1]),
                                              assignee=self.assignee,
                                              issue_hash=item.get_meta("issue_hash", "")))
        log.info("Creating findings")


    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(len(data_obj), "org", "organization", comment="Azure DevOps organization name")
        data_obj.insert(len(data_obj), "project", "proj", comment="Azure DevOps Project name")
        data_obj.insert(len(data_obj), "pat", "personalAccessToken", comment="Azure DevOps personal Access Token")
        data_obj.insert(len(data_obj), "team", "team", comment="Azure DevOps Team (default: none)")
        data_obj.insert(len(data_obj), "issue_type", "task", comment="Azure DevOps Issue Type (default: task)")
        data_obj.insert(len(data_obj), "assignee", "assignee",
                        comment="Azure DevOps Assignee for issue (default: none)")
        data_obj.insert(len(data_obj), "custom_fields", "{}", comment="Key-Value list of assignee for workitem")

    @staticmethod
    def get_name():
        """ Reporter name """
        return "AzureDevOps"

    @staticmethod
    def get_description():
        """ Reporter description """
        return "Azure DevOps REST API reporter"
