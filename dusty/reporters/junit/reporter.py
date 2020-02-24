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
    Reporter: junit
"""

from junit_xml import TestSuite, TestCase

from dusty.tools import log, markdown
from dusty.models.module import DependentModuleModel
from dusty.models.reporter import ReporterModel
from dusty.models.finding import DastFinding, SastFinding
from dusty.constants import SEVERITIES

from . import constants


class Reporter(DependentModuleModel, ReporterModel):
    """ Report findings from scanners """

    def __init__(self, context):
        """ Initialize reporter instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["reporters"][__name__.split(".")[-2]]

    def report(self):
        """ Report """
        file = self.config.get("file", constants.DEFAULT_REPORT_FILE)
        if self.config.get("format_file_name", True):
            file = file.format(**self.context.meta)
        log.info("Creating XML report %s", file)
        # Prepare test cases
        test_name = \
            f"{self.context.get_meta('project_name', 'UnnamedProject')}-" \
            f"{self.context.get_meta('environment_name', 'unknown')}-" \
            f"{self.context.get_meta('testing_type', 'AST')}"
        test_cases = list()
        # Summary
        summary_case = TestCase(
            f"Security tests has been COMPLETED",
            classname="Carrier Dusty",
            stdout=\
                f"Total findings (with false positives and info): {len(self.context.findings)}. " \
                f"Total scan errors: {len(self.context.errors)}."
        )
        test_cases.append(summary_case)
        # Findings
        for item in self.context.findings:
            if item.get_meta("information_finding", False) or \
                    item.get_meta("false_positive_finding", False) or \
                    item.get_meta("excluded_finding", False):
                continue
            if isinstance(item, DastFinding):
                test_case = TestCase(item.title, classname=item.get_meta("tool", ""))
                test_case.add_error_info(
                    message=markdown.markdown_to_text(item.description) if \
                        self.config.get("plain_text", False) else \
                        markdown.markdown_unescape(item.description),
                    error_type=item.get_meta("severity", SEVERITIES[-1])
                )
                test_cases.append(test_case)
            if isinstance(item, SastFinding):
                test_case = TestCase(item.title, classname=item.get_meta("tool", ""))
                test_case.add_error_info(
                    message=markdown.markdown_to_text("\n\n".join(item.description)) if \
                        self.config.get("plain_text", False) else \
                        markdown.markdown_unescape("\n\n".join(item.description)),
                    error_type=item.get_meta("severity", SEVERITIES[-1])
                )
                test_cases.append(test_case)
        # Save to file
        with open(file, "w") as report:
            TestSuite.to_file(report, [TestSuite(test_name, test_cases)], prettyprint=False)
        self.set_meta("report_file", file)

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(len(data_obj), "file", "/path/to/report.xml", comment="XML report path")
        data_obj.insert(
            len(data_obj), "format_file_name", True,
            comment="(optional) Allow to use {variables} inside file path"
        )
        data_obj.insert(
            len(data_obj), "plain_text", False,
            comment="(optional) Convert markdown to plain text"
        )

    @staticmethod
    def get_name():
        """ Reporter name """
        return "JUnit"

    @staticmethod
    def get_description():
        """ Reporter description """
        return "JUnit XML reporter"
