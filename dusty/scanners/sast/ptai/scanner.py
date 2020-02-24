#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,E0401,W0702,W0703

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
    Scanner: PT AI
"""

import os
import traceback

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.scanner import ScannerModel
from dusty.models.error import Error

from .parser import parse_findings


class Scanner(DependentModuleModel, ScannerModel):
    """ Scanner class """

    def __init__(self, context):
        """ Initialize scanner instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["scanners"][__name__.split(".")[-3]][__name__.split(".")[-2]]

    def execute(self):
        """ Run the scanner """
        path = self.config.get("code")
        # Collect reports to parse
        reports = list()
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for name in files:
                    reports.append(os.path.join(root, name))
        else:
            reports.append(path)
            if self.config.get("mail_report", True):
                if self.config.get("rename_mail_attachment", True):
                    filename = self.config.get(
                        "rename_pattern",
                        "PTAI_{project_name}_{testing_type}_{scan_type}_{build_id}.html"
                    ).format(**self.context.meta)
                    attachment = (path, filename)
                    self.set_meta("report_file", attachment)
                else:
                    self.set_meta("report_file", path)
        # Parse reports
        for report in reports:
            try:
                parse_findings(report, self)
            except:
                error = f"Failed to parse PT AI report {report}"
                log.exception(error)
                self.errors.append(Error(
                    tool=self.get_name(),
                    error=error,
                    details=f"```\n{traceback.format_exc()}\n```"
                ))

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj),
            "code", "/path/to/code",
            comment="PT AI report HTML file or folder with PT AI HTML reports"
        )
        data_obj.insert(
            len(data_obj),
            "filtered_statuses", "discarded, suspected",
            comment="(optional) finding statuses to filter-out"
        )
        data_obj.insert(
            len(data_obj),
            "mail_report", True,
            comment="(optional) attach report to email (if email reporter is enabled)"
        )
        data_obj.insert(
            len(data_obj),
            "rename_mail_attachment", True,
            comment="(optional) rename email attachment"
        )
        data_obj.insert(
            len(data_obj),
            "rename_pattern", "{project_name}_{testing_type}_{scan_type}_{build_id}.html",
            comment="(optional) pattern to rename email attachment to"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["code"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def get_name():
        """ Module name """
        return "PT AI"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "PT AI scanner report parser"
