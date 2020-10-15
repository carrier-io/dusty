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
    Trivy JSON parser
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
    # Severity mapping
    severity_mapping = {
        "UNKNOWN": "Info",
        "LOW": "Low",
        "MEDIUM": "Medium",
        "HIGH": "High",
        "CRITICAL": "Critical",
    }
    # Parse JSON
    if not isinstance(data, list) or not data:
        log.info("No data in report")
        return
    # Make finding instances
    for data_block in data:
        if not data_block.get("Vulnerabilities", list()):
            log.info("Skipping empty data block: %s", data_block.get("Target", data_block))
            continue
        for item in data_block.get("Vulnerabilities", list()):
            #
            vuln_id = item.get("VulnerabilityID", "")
            vuln_pkgname = item.get("PkgName", "")
            vuln_installed_version = item.get("InstalledVersion", "")
            vuln_fixed_version = item.get("FixedVersion", "")
            vuln_layer = item.get("Layer", dict()).get("DiffID", "")
            #
            vuln_title = item.get("Title", "-")
            if vuln_id:
                vuln_title = f"{vuln_id}: {vuln_title}"
            if vuln_pkgname:
                vuln_title = f"{vuln_pkgname}: {vuln_title}"
            #
            if not scanner.config.get("show_with_temp_id", False) and \
                    vuln_id.startswith("TEMP-"):
                log.info("Skipping finding with TEMP ID: %s", vuln_title)
                continue
            if not scanner.config.get("show_without_description", True) and \
                    "Description" not in item:
                log.info("Skipping finding without description: %s", vuln_title)
                continue
            #
            vuln_severity = severity_mapping[item.get("Severity", "UNKNOWN")]
            vuln_file = vuln_layer
            #
            vuln_info_chunks = list()
            #
            vuln_info_chunks.append(markdown.markdown_escape(item.get("Description", "-")))
            #
            if vuln_id:
                vuln_info_chunks.append(f"**VulnerabilityID:** {markdown.markdown_escape(vuln_id)}")
            if vuln_pkgname:
                vuln_info_chunks.append(f"**PkgName:** {markdown.markdown_escape(vuln_pkgname)}")
            if vuln_installed_version:
                vuln_info_chunks.append(
                    f"**InstalledVersion:** {markdown.markdown_escape(vuln_installed_version)}"
                )
            if vuln_fixed_version:
                vuln_info_chunks.append(
                    f"**FixedVersion:** {markdown.markdown_escape(vuln_fixed_version)}"
                )
            if vuln_layer:
                vuln_info_chunks.append(f"**Layer DiffID:** {markdown.markdown_escape(vuln_layer)}")
            #
            vuln_refs = item.get("References", list())
            if vuln_refs:
                vuln_info_chunks.append("**References:**")
                for vuln_ref in vuln_refs:
                    vuln_info_chunks.append(markdown.markdown_escape(vuln_ref))
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
