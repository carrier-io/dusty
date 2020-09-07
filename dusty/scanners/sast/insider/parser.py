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
    Insider JSON parser
"""

import json
from collections import namedtuple
import pkg_resources

from dusty.tools import log, markdown
from dusty.models.finding import SastFinding


def parse_findings(filename, scanner):
    """ Parse findings """
    # Load JSON
    try:
        with open(filename, "r") as file:
            data = json.load(file)
    except:  # pylint: disable=W0702
        log.exception("Failed to load report JSON")
        return
    # Load CWE map
    cwe_map = json.loads(
        pkg_resources.resource_string(
            "dusty",
            f"{'/'.join(__name__.split('.')[1:-1])}/data/cwe_map_v4.2.json"
        )
    )
    # Parse JSON
    if not isinstance(data, dict) or "vulnerabilities" not in data:
        log.info("No data in report")
        return
    # Make finding instances
    for item in data["vulnerabilities"]:
        vuln_severity = cvss_to_severity(item.get("cvss", 0.0))
        vuln_cwe = item.get("cwe", "Vulnerability")
        #
        vuln_cwe_title = cwe_map[vuln_cwe] if vuln_cwe in cwe_map else vuln_cwe
        vuln_file_title = f" in {item.get('classMessage')}" if "classMessage" in item else ""
        vuln_title = f"{vuln_cwe_title}{vuln_file_title}"
        #
        vuln_file = item.get("classMessage", "").rsplit(" (", 1)[0]
        #
        vuln_info_chunks = list()
        if "longMessage" in item:
            vuln_info_chunks.append(markdown.markdown_escape(item["longMessage"]))
        if "shortMessage" in item:
            vuln_info_chunks.append(markdown.markdown_escape(item["shortMessage"]))
        vuln_info_chunks.append(f"**Class:** {markdown.markdown_escape(item['classMessage'])}")
        vuln_info_chunks.append(f"**Method:** {markdown.markdown_escape(item['method'])}")
        if "affectedFiles" in item:
            vuln_info_chunks.append(
                f"**Files:** {markdown.markdown_escape(', '.join(item['affectedFiles']))}"
            )
        #
        finding = SastFinding(
            title=vuln_title,
            description=[
                "\n\n".join(vuln_info_chunks)
            ]
        )
        finding.set_meta("tool", scanner.get_name())
        finding.set_meta("severity", vuln_severity)
        finding.set_meta("legacy.file", vuln_file)
        endpoints = list()
        if vuln_file:
            endpoints.append(namedtuple("Endpoint", ["raw"])(raw=vuln_file))
        finding.set_meta("endpoints", endpoints)
        log.debug(f"Endpoints: {finding.get_meta('endpoints')}")
        scanner.findings.append(finding)


def cvss_to_severity(cvss):
    """ Map CVSS score to Carrier severity """
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss >= 0.1:
        return "Low"
    return "Info"
