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
    masscan JSON parser
"""

import json

from dusty.tools import log, markdown
from dusty.models.finding import DastFinding
from dusty.constants import SEVERITIES


def parse_findings(output_file, scanner):
    """ Parse findings (code from dusty 1.0) """
    log.debug("Parsing findings")
    # Load JSON
    with open(output_file, "rb") as json_file:
        data = json.load(json_file)
    # Walk results
    for issue in data:
        title = f'Open port {issue["ports"][0]["port"]} found on {issue["ip"]}'
        finding = DastFinding(
            title=title,
            description=markdown.markdown_escape(title)
        )
        finding.set_meta("tool", scanner.get_name())
        finding.set_meta("severity", SEVERITIES[-1])
        scanner.findings.append(finding)
