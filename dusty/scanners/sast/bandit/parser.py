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
    Bandit JSON parser
"""

import json
from collections import namedtuple
import pkg_resources

from dusty.tools import log, markdown
from dusty.models.finding import SastFinding

from .legacy import BanditParser
from . import constants


def parse_findings(data, scanner):
    """ Parse findings """
    # Parse JSON using legacy parser
    findings = BanditParser(data).items
    # Make finding instances
    for item in findings:
        finding = SastFinding(
            title=item["title"],
            description=[
                "\n\n".join([
                    f"```\n{item['description']}\n```",
                    f"**Mitigation:** {markdown.markdown_escape(item['mitigation'])}",
                    f"**Impact:** {markdown.markdown_escape(item['impact'])}",
                    f"**References:** {markdown.markdown_escape(item['references'])}",
                    f"**File to review:** {markdown.markdown_escape(item['file_path'])}" \
                        f":{item['line']}"
                ])
            ]
        )
        # Better bandit finding titles/descriptions
        database = json.load(pkg_resources.resource_stream(
            "dusty",
            f"{'/'.join(__name__.split('.')[1:-1])}/data/findings.json"
        ))
        if item["bandit_id"] in database:
            db_item = database[item["bandit_id"]]
            finding.set_meta("rewrite_title_to", db_item["title"])
            if db_item.get("description", None):
                finding.description[0] = "\n\n".join([
                    markdown.markdown_escape(db_item["description"]),
                    finding.description[0]
                ])
        # Other meta
        finding.set_meta("tool", scanner.get_name())
        finding.set_meta("severity", constants.BANDIT_SEVERITIES[item["severity"]])
        finding.set_meta("legacy.file", item["file_path"])
        finding.set_meta("legacy.line", item["line"])
        finding.set_meta("confidence", item["confidence"])
        finding.set_meta("endpoints", [namedtuple("Endpoint", ["raw"])(raw=item["file_path"])])
        log.debug(f"Endpoints: {finding.get_meta('endpoints')}")
        scanner.findings.append(finding)
