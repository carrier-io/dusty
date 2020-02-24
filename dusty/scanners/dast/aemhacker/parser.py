#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,W1401

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
    AEM Hacker output parser
"""

import re

from dusty.tools import log, markdown, url
from dusty.models.finding import DastFinding


def parse_findings(data, scanner):
    """ Parse findings """
    log.debug("Parsing findings")
    item_regex = re.compile(
        "".join([
            "^(\[\+\] New Finding!!!)$",
            "\s*Name: (?P<name>.*)$",
            "\s*Url: (?P<url>.*)$",
            "\s*Description: (?P<description>[\s\S]*?)\n\n"
        ]),
        re.MULTILINE
    )
    for item in item_regex.finditer(data):
        # Make finding object
        description = list()
        description.append(markdown.markdown_escape(item.group("description")))
        description.append(f'\n**URL:** {markdown.markdown_escape(item.group("url"))}')
        description = "\n".join(description)
        finding = DastFinding(
            title=item.group("name"),
            description=description
        )
        finding.set_meta("tool", scanner.get_name())
        finding.set_meta("severity", "Info")
        # Endpoints (for backwards compatibility)
        endpoints = list()
        endpoint = url.parse_url(item.group("url"))
        endpoints.append(endpoint)
        finding.set_meta("endpoints", endpoints)
        log.debug(f"Endpoints: {finding.get_meta('endpoints')}")
        # Done
        scanner.findings.append(finding)
