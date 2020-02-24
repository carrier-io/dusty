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
    w3af XML parser
"""

import base64
import hashlib

from urllib.parse import urlparse
from lxml import etree

from dusty.tools import log, url, markdown
from dusty.models.finding import DastFinding

from . import constants


def parse_findings(output_file, scanner):
    """ Parse findings (code from dusty 1.0) """
    log.debug("Parsing findings")
    parser = etree.XMLParser(resolve_entities=False, huge_tree=True)
    w3scan = etree.parse(output_file, parser)
    root = w3scan.getroot()
    dupes = dict()
    for vulnerability in root.findall("vulnerability"):
        name = vulnerability.attrib["name"]
        severity = constants.W3AF_SEVERITIES[vulnerability.attrib["severity"]]
        description = "%s are:\n\n" % vulnerability.find("description").text.split("are:")[0]
        transactions = vulnerability.find("http-transactions")
        if transactions is not None:
            transactions = transactions.findall("http-transaction")
        for transaction in transactions:
            request = transaction.find("http-request")
            response = transaction.find("http-response")
            status = request.find("status").text.split(" ")
            response_code = response.find("status").text.split(" ")[1]
            http_method = status[0]
            request_url = status[1]
            data = ""
            for part in [request, response]:
                headers = [f"{h.attrib['field']} -> {h.attrib['content']}" \
                        for h in part.find("headers").findall("header")]
                headers = "\n".join(headers)
                request_body = part.find("body")
                if request_body.attrib["content-encoding"] == "base64":
                    if request_body.text:
                        request_body = base64.b64decode(
                            request_body.text
                        ).decode("utf-8", errors="ignore")
                    else:
                        request_body = ""
                else:
                    request_body = request_body.text if request_body.text else ""
                if not data:
                    data = f"Request: {request_url} {http_method} {response_code} \n\n"
                else:
                    data += "Response: \n"
                data += f"Headers: {headers}\n\nBody:{request_body}\n\n"
            dupe_url = urlparse(request_url)
            # Creating dupe path: need to think on more intelligent implementation
            dupe_path = dupe_url.path[:dupe_url.path.index("%")] \
                    if "%" in dupe_url.path else dupe_url.path
            dupe_path = dupe_path[:dupe_path.index("+")] if "+" in dupe_path else dupe_path
            dupe_path = dupe_path[:dupe_path.index(".")] if "." in dupe_path else dupe_path
            dupe_path = dupe_path[:dupe_path.rindex("/")] if "/" in dupe_path else dupe_path
            dupe_url = f"{dupe_url.scheme}://{dupe_url.netloc}{dupe_path}"
            dupe_code = f"{str(response_code)[0]}xx"
            dupe_key = hashlib.md5(
                f"{name} {dupe_url} {http_method} {dupe_code}".encode("utf-8")
            ).hexdigest()
            # Create finding data dictionary
            if dupe_key not in dupes:
                dupes[dupe_key] = {
                    "title": f"{name} {dupe_url} {dupe_code}",
                    "description": description,
                    "severity": severity,
                    "references": data,
                    "endpoints": list()
                }
            elif data not in dupes[dupe_key]["references"]:
                dupes[dupe_key]["references"] += data
            if request_url not in dupes[dupe_key]["endpoints"]:
                dupes[dupe_key]["description"] += f"- {request_url}\n\n"
                dupes[dupe_key]["endpoints"].append(request_url)
    # Create finding objects
    for item in dupes.values():
        description = f"{markdown.markdown_escape(item['description'])}\n\n"
        description += f"**References:**\n {markdown.markdown_escape(item['references'])}\n\n"
        # Make finding object
        finding = DastFinding(
            title=item["title"],
            description=description
        )
        finding.set_meta("tool", scanner.get_name())
        finding.set_meta("severity", item["severity"])
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
