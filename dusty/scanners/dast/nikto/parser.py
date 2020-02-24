#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,W1401,E0401,R0914,R0915,R0912,C0103

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
    Nikto XML parser

    Original author: aaronweaver
    Modified for Dusty 1.0 by: arozumenko
    Ported to Dusty 2.0 by: LifeDJIK
"""

import re
import hashlib
from defusedxml import ElementTree as ET

from dusty.tools import log, url, markdown
from dusty.models.finding import DastFinding
from dusty.constants import SEVERITIES


def parse_findings(output_file, scanner):
    """ Parse findings (code from dusty 1.0) """
    log.debug("Parsing findings")
    dupes = dict()
    #
    tree = ET.parse(output_file)
    root = tree.getroot()
    new_root = root.find("niktoscan")
    scan = new_root.find("scandetails")
    #
    for item in scan.findall("item"):
        # Title
        titleText = None
        description = item.find("description").text
        # Cut the title down to the first sentence
        sentences = re.split(
            r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?)\s', description)
        if sentences:
            titleText = sentences[0][:900]
        else:
            titleText = description[:900]
        #
        # Url
        ip = item.find("iplink").text
        # Remove the port numbers for 80/443
        ip = ip.replace(":80", "")
        ip = ip.replace(":443", "")
        #
        # Description
        description = "\nHost: " + ip + "\n" + item.find("description").text
        dupe_key = hashlib.md5(description.encode("utf-8")).hexdigest()
        #
        if dupe_key in dupes:
            finding = dupes[dupe_key]
            if finding["description"]:
                finding["description"] = \
                    finding["description"] + "\nHost:" + ip + "\n" + description
            finding["endpoints"].append(ip)
            dupes[dupe_key] = finding
        else:
            dupes[dupe_key] = True
            finding = {
                "title": titleText,
                "description": description,
                "endpoints": list()
            }
            dupes[dupe_key] = finding
            finding["endpoints"].append(ip)
    # Create finding objects
    for item in dupes.values():
        finding = DastFinding(
            title=item["title"],
            description=markdown.markdown_escape(item["description"])
        )
        finding.set_meta("tool", scanner.get_name())
        finding.set_meta("severity", SEVERITIES[-1])
        # Endpoints (for backwards compatibility)
        endpoints = list()
        for entry in item["endpoints"]:
            endpoint = url.parse_url(entry)
            if endpoint in endpoints:
                continue
            endpoints.append(endpoint)
        finding.set_meta("endpoints", endpoints)
        log.debug(f"Endpoints: {finding.get_meta('endpoints')}")
        # Done
        scanner.findings.append(finding)
