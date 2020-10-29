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
    Reporter: reportportal
"""

from dusty.tools import log, markdown
from dusty.models.module import DependentModuleModel
from dusty.models.reporter import ReporterModel
from dusty.models.finding import DastFinding, SastFinding
from dusty.constants import SEVERITIES

from .legacy import launch_reportportal_service


class Reporter(DependentModuleModel, ReporterModel):
    """ Report findings from scanners """

    def __init__(self, context):
        """ Initialize reporter instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["reporters"][__name__.split(".")[-2]]
        # Prepare config object (code from legacy 'parse_rp_config')
        self._rp_config = {
            "rp_project": self.config.get("rp_project_name", "Dusty"),
            "rp_launch_name": self.config.get("rp_launch_name", self.context.suite),
            "rp_url": self.config.get("rp_host"),
            "rp_token": self.config.get("rp_token"),
        }
        self._rp_config["rp_launch_tags"] = self.config.get("rp_launch_tags", None)
        self._rp_client = None

    def on_start(self):
        """ Called when testing starts """
        log.info("Starting ReportPortal launch")
        self._rp_client = launch_reportportal_service(self._rp_config)

    def report(self):
        """ Report """
        if not self._rp_client:
            log.warning("ReportPortal configuration/connection is invalid. Skipping RP reporting")
            return
        log.info("Reporting to ReportPortal")
        for item in self.context.findings:
            if item.get_meta("information_finding", False) or \
                    item.get_meta("false_positive_finding", False) or \
                    item.get_meta("excluded_finding", False):
                continue
            if isinstance(item, DastFinding):
                item_details = markdown.markdown_unescape(item.description)
                item_description = item_details
                tags = [
                    f'Tool: {item.get_meta("tool", "")}',
                    f'TestType: {self.context.get_meta("testing_type", "DAST")}',
                    f'Severity: {item.get_meta("severity", SEVERITIES[-1])}'
                ]
                if item.get_meta("confidence", None):
                    tags.append(f'Confidence: {item.get_meta("confidence")}')
                item_id = self._rp_client.start_test_item(item.title, description=item_description)
                if item.get_meta("legacy.images", None):
                    for attachment in item.get_meta("legacy.images"):
                        self._rp_client.test_item_message(attachment["name"], "INFO", attachment)
                self._rp_client.test_item_message("!!!MARKDOWN_MODE!!! %s " % item_details, "INFO")
                self._rp_client.test_item_message(item.get_meta("issue_hash", "<no_hash>"), "ERROR")
                self._rp_client.finish_test_item(item_id)
            elif isinstance(item, SastFinding):
                item_details = markdown.markdown_unescape("\n\n".join(item.description))
                item_description = item_details
                tags = [
                    f'Tool: {item.get_meta("tool", "")}',
                    f'TestType: {self.context.get_meta("testing_type", "SAST")}',
                    f'Severity: {item.get_meta("severity", SEVERITIES[-1])}'
                ]
                if item.get_meta("confidence", None):
                    tags.append(f'Confidence: {item.get_meta("confidence")}')
                item_id = self._rp_client.start_test_item(item.title, description=item_description)
                self._rp_client.test_item_message("!!!MARKDOWN_MODE!!! %s " % item_details, "INFO")
                self._rp_client.test_item_message(item.get_meta("issue_hash", "<no_hash>"), "ERROR")
                self._rp_client.finish_test_item(item_id)
            else:
                log.warning("Unsupported finding type")
                continue # raise ValueError("Unsupported item type")
        self._rp_client.finish_test()

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj),
            "rp_host", "https://rp.com",
            comment="url to ReportPortal.io deployment"
        )
        data_obj.insert(
            len(data_obj),
            "rp_token", "XXXXXXXXXXXXX",
            comment="ReportPortal authentication token"
        )
        data_obj.insert(
            len(data_obj),
            "rp_project_name", "XXXXXX",
            comment="Name of a Project in ReportPortal to send results to"
        )
        data_obj.insert(
            len(data_obj),
            "rp_launch_name", "XXXXXXX",
            comment="Name of a Launch in ReportPortal to send results to"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["rp_project_name", "rp_launch_name", "rp_host", "rp_token"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def get_name():
        """ Reporter name """
        return "ReportPortal"

    @staticmethod
    def get_description():
        """ Reporter description """
        return "ReportPortal reporter"
