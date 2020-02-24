#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,W1401,E0401,R0914,R0915,R0912

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
    PT AI HTML parser
"""

import html
from collections import namedtuple

from dusty.tools import log, markdown
from dusty.models.finding import SastFinding

from .legacy import PTAIScanParser
from . import constants


def parse_findings(output_file, scanner):  # pylint: disable=E,W,R,C
    """ Parse findings (code from dusty 1.0) """
    # Parse HTML report using legacy parser
    filtered_statuses = scanner.config.get(
        "filtered_statuses", constants.PTAI_DEFAULT_FILTERED_STATUSES
    )
    if isinstance(filtered_statuses, str):
        filtered_statuses = [item.strip() for item in filtered_statuses.split(",")]
    findings = PTAIScanParser(output_file, filtered_statuses).items
    for item in findings:
        finding = SastFinding(
            title=item["title"],
            description=[
                html.escape(markdown.markdown_escape(
                    item["description"].replace("                        ", "")
                )) + f"\n\n**File to review:** {markdown.markdown_escape(item['file_path'])}"
            ] + [html.escape(data) for data in item["steps_to_reproduce"]]
        )
        finding.set_meta("tool", scanner.get_name())
        finding.set_meta("severity", constants.PTAI_SEVERITIES[item["severity"]])
        finding.set_meta("legacy.file", item["file_path"])
        finding.set_meta("endpoints", [namedtuple("Endpoint", ["raw"])(raw=item["file_path"])])
        log.debug(f"Endpoints: {finding.get_meta('endpoints')}")
        scanner.findings.append(finding)
