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
    AEM Hacker scanner output parser
"""

import re

from collections import namedtuple
from markdownify import markdownify as md
from dusty.data_model.canonical_model import Endpoint, DefaultModel as Finding


class AemOutputParser(object):
    """ Parses aem-hacker output and populates finding list """

    def __init__(self, aem_hacker_output):
        tool = "AEM Hacker"
        severity = "Info"
        item_regex = re.compile(
            "".join([
                "^(\[\+\] New Finding!!!)$",
                "\s*Name: (?P<name>.*)$",
                "\s*Url: (?P<url>.*)$",
                "\s*Description: (?P<description>[\s\S]*?)\n\n"
            ]),
            re.MULTILINE
        )
        # Populate items
        self.items = list()
        for item in item_regex.finditer(aem_hacker_output):
            finding = Finding(
                title=item.group("name"),
                url=item.group("url"),
                description=md(item.group("description")),
                tool=tool,
                test=tool,
                severity=severity,
                active=False,
                verified=False,
                dynamic_finding=True,
                numerical_severity=Finding.get_numerical_severity(severity)
            )
            finding.unsaved_endpoints = [
                make_endpoint_from_url(item.group("url"))
            ]
            self.items.append(finding)


def make_endpoint_from_url(url):
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
        query=parsed_url.query,
        fragment=parsed_url.fragment
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
