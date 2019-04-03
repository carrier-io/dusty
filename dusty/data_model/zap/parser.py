#!/usr/bin/python3
# coding=utf-8
# pylint: disable=W1401,R0903

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
    ZAP scanner json parser
"""

import re
import json
import html

from collections import namedtuple
from markdownify import markdownify as md

from dusty import constants as c
from dusty.data_model.canonical_model import Endpoint, DefaultModel as Finding


class ZapJsonParser(object):
    """ Parses ZAP json report and populates finding list """

    def __init__(self, zap_result, tool_name):
        zap_json = json.loads(zap_result)
        # Populate items
        self.items = list()
        for site in zap_json["site"]:
            for alert in site["alerts"]:
                description = list()
                if "desc" in alert:
                    description.append(md(alert["desc"]))
                if "solution" in alert:
                    description.append(f'**Solution**:\n {md(alert["solution"])}')
                if "reference" in alert:
                    description.append(f'**Reference**:\n {md(alert["reference"])}')
                if "otherinfo" in alert:
                    description.append(f'**Other information**:\n {md(alert["otherinfo"])}')
                description.append(f'**Confidence**: {md(c.ZAP_CONFIDENCES[alert["confidence"]])}')
                description = "\n".join(description)
                instances = list()
                if alert["instances"]:
                    instances.append("\n")
                    instances.append("URI | Method | Parameter | Attack | Evidence")
                    instances.append("--- | --- | --- | --- | ---")
                for item in alert["instances"]:
                    instances.append(" | ".join([
                        html.escape(md_table_escape(item.get("uri", "-"))),
                        html.escape(md_table_escape(item.get("method", "-"))),
                        html.escape(md_table_escape(item.get("param", "-"))),
                        html.escape(md_table_escape(item.get("attack", "-"))),
                        html.escape(md_table_escape(item.get("evidence", "-")))
                    ]))
                finding = Finding(
                    title=alert["name"],
                    url=site["@name"],
                    description=description,
                    payload="\n".join(instances),
                    tool=tool_name,
                    test=tool_name,
                    severity=c.ZAP_SEVERITIES[alert["riskcode"]],
                    active=False,
                    verified=False,
                    dynamic_finding=True,
                    numerical_severity=Finding.get_numerical_severity(
                        c.ZAP_SEVERITIES[alert["riskcode"]]
                    )
                )
                finding.unsaved_endpoints = list()
                added_endpoints = set()
                for item in alert["instances"]:
                    if not item.get("uri", None):
                        continue
                    endpoint = make_endpoint_from_url(
                        item.get("uri"),
                        include_query=False, include_fragment=False
                    )
                    if str(endpoint) in added_endpoints:
                        continue
                    finding.unsaved_endpoints.append(endpoint)
                    added_endpoints.add(str(endpoint))
                self.items.append(finding)


def md_table_escape(string):
    return string.replace("\n", " ").replace("_", "\\_")


def make_endpoint_from_url(url, include_query=True, include_fragment=True):
    """ Makes Enpoint instance from URL """
    parsed_url = parse_url(url)
    host_value = parsed_url.hostname
    protocol = parsed_url.protocol
    port = parsed_url.port
    if (protocol == "http" and port != "80") or (
            protocol == "https" and port != "443"):
        host_value = f'{parsed_url.hostname}:{parsed_url.port}'
    return Endpoint(
        protocol=parsed_url.protocol,
        host=host_value,
        fqdn=parsed_url.hostname,
        port=parsed_url.port,
        path=parsed_url.path,
        query=parsed_url.query if include_query else "",
        fragment=parsed_url.fragment if include_fragment else ""
    )


def parse_url(url):
    """ Parses URL into parts """
    parsed_url = re.search("".join([
        "^\s*((?P<protocol>.*?)\:\/\/)?",
        "((?P<username>.*?)(\:(?P<password>.*))?\@)?",
        "((?P<hostname>.*?)(\:((?P<port>[0-9]+)))?)(?P<path>/.*?)?",
        "(?P<query>\?.*?)?(?P<fragment>\#.*?)?\s*$"
    ]), url)
    protocol = parsed_url.group("protocol")
    hostname = parsed_url.group("hostname")
    port = parsed_url.group("port")
    path = parsed_url.group("path")
    query = parsed_url.group("query")
    fragment = parsed_url.group("fragment")
    username = parsed_url.group("username")
    password = parsed_url.group("password")
    # Prepare result object
    result = namedtuple("URL", [
        "protocol", "hostname", "port",
        "path", "query", "fragment",
        "username", "password"
    ])
    return result(
        protocol=protocol if protocol is not None else "",
        hostname=hostname if hostname is not None else "",
        port=port if port is not None else "",
        path=path if path is not None else "/",
        query=query[1:] if query is not None else "",
        fragment=fragment[1:] if fragment is not None else "",
        username=username if username is not None else "",
        password=password if password is not None else ""
    )
