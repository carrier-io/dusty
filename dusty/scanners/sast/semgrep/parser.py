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
    Semgrep JSON parser
"""

import json
from collections import namedtuple

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
    # Parse JSON
    if not isinstance(data, dict) or "results" not in data:
        log.info("No data in report")
        return
    # Make finding instances
    for item in data["results"]:
        vuln_data = item.get("extra", dict())
        vuln_meta = vuln_data.get("metadata", dict())
        #
        vuln_rule = item["check_id"]
        vuln_file = item["path"]
        vuln_info = vuln_data.get("message", "")
        vuln_severity = map_severity(vuln_data.get("severity", ""))
        #
        vuln_cwe_owasp_title = vuln_meta.get("cwe", "")
        if not vuln_cwe_owasp_title:
            vuln_cwe_owasp_title = vuln_meta.get("owasp", "")
        if not vuln_cwe_owasp_title:
            vuln_cwe_owasp_title = "Vulnerability"
        #
        vuln_title = f"{vuln_cwe_owasp_title} in {vuln_file}"
        #
        vuln_info_chunks = list()
        if vuln_info:
            vuln_info_chunks.append(markdown.markdown_escape(vuln_info))
        vuln_info_chunks.append(f"**Rule:** {markdown.markdown_escape(vuln_rule)}")
        if "source-rule-url" in vuln_meta:
            vuln_info_chunks.append(
                f"**Rule source:** {markdown.markdown_escape(vuln_meta['source-rule-url'])}"
            )
        if "cwe" in vuln_meta:
            vuln_info_chunks.append(f"**CWE:** {markdown.markdown_escape(vuln_meta['cwe'])}")
        if "owasp" in vuln_meta:
            vuln_info_chunks.append(f"**OWASP:** {markdown.markdown_escape(vuln_meta['owasp'])}")
        if "lines" in vuln_data:
            vuln_info_chunks.append(f"**Lines:** {markdown.markdown_escape(vuln_data['lines'])}")
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


def map_severity(meta_severity):
    """ Map scanner severity to Carrier severity """
    severity_map = {
        "INFO": "Info",
        "WARNING": "Medium",
        "ERROR": "High",
    }
    return severity_map.get(meta_severity, "Info")
