#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,E0401,W0702,W0703,R0902,R0912

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
    OWASP ZAP JSON parser
"""

import json
import html

from dusty.tools import log, markdown, url
from dusty.models.finding import DastFinding

from . import constants


def parse_findings(data, scanner):
    """ Parse findings """
    log.debug("Parsing findings")
    zap_json = json.loads(data)
    for site in zap_json["site"]:
        for alert in site["alerts"]:
            description = list()
            if "desc" in alert:
                description.append(markdown.html_to_text(alert["desc"]))
            if "solution" in alert:
                description.append(
                    f'\n**Solution:**\n {markdown.html_to_text(alert["solution"])}')
            if "reference" in alert:
                description.append(
                    f'\n**Reference:**\n {markdown.html_to_text(alert["reference"])}')
            if "otherinfo" in alert:
                description.append(
                    f'\n**Other information:**\n {markdown.html_to_text(alert["otherinfo"])}')
            if alert["instances"]:
                description.append("\n**Instances:**\n")
                description.append("| URI | Method | Parameter | Attack | Evidence |")
                description.append("| --- | ------ | --------- | ------ | -------- |")
            # Prepare results
            finding_data = list()
            if scanner.config.get("split_by_endpoint", False):
                # Collect endpoints
                endpoints = list()
                for item in alert["instances"]:
                    if not item.get("uri", None):
                        continue
                    endpoint = url.parse_url(item.get("uri"))
                    if endpoint in endpoints:
                        continue
                    endpoints.append(endpoint)
                # Prepare data
                for endpoint in endpoints:
                    finding_data.append({
                        "title": f'{alert["name"]} on {endpoint.raw}',
                        "description": "\n".join(description + ["| {} |".format(" | ".join([
                            html.escape(markdown.markdown_table_escape(item.get("uri", "-"))),
                            html.escape(markdown.markdown_table_escape(item.get("method", "-"))),
                            html.escape(markdown.markdown_table_escape(item.get("param", "-"))),
                            html.escape(markdown.markdown_table_escape(item.get("attack", "-"))),
                            html.escape(markdown.markdown_table_escape(item.get("evidence", "-")))
                            ])) for item in alert["instances"] \
                                if item.get("uri", None) == endpoint.raw]),
                        "tool": scanner.get_name(),
                        "severity": constants.ZAP_SEVERITIES[alert["riskcode"]],
                        "confidence": constants.ZAP_CONFIDENCES[alert["confidence"]],
                        "endpoints": [endpoint]
                    })
            # Make one finding object if needed/requested
            if not finding_data:
                # Extend description
                for item in alert["instances"]:
                    description.append("| {} |".format(" | ".join([
                        html.escape(markdown.markdown_table_escape(item.get("uri", "-"))),
                        html.escape(markdown.markdown_table_escape(item.get("method", "-"))),
                        html.escape(markdown.markdown_table_escape(item.get("param", "-"))),
                        html.escape(markdown.markdown_table_escape(item.get("attack", "-"))),
                        html.escape(markdown.markdown_table_escape(item.get("evidence", "-")))
                    ])))
                # Endpoints (for backwards compatibility)
                endpoints = list()
                for item in alert["instances"]:
                    if not item.get("uri", None):
                        continue
                    endpoint = url.parse_url(item.get("uri"))
                    if endpoint in endpoints:
                        continue
                    endpoints.append(endpoint)
                # Data
                finding_data.append({
                    "title": alert["name"],
                    "description": "\n".join(description),
                    "tool": scanner.get_name(),
                    "severity": constants.ZAP_SEVERITIES[alert["riskcode"]],
                    "confidence": constants.ZAP_CONFIDENCES[alert["confidence"]],
                    "endpoints": endpoints
                })
            # Make finding objects
            for object_data in finding_data:
                finding = DastFinding(
                    title=object_data["title"],
                    description=object_data["description"]
                )
                finding.set_meta("tool", object_data["tool"])
                finding.set_meta("severity", object_data["severity"])
                finding.set_meta("confidence", object_data["confidence"])
                finding.set_meta("endpoints", object_data["endpoints"])
                log.debug(f"Endpoints: {finding.get_meta('endpoints')}")
                scanner.findings.append(finding)
