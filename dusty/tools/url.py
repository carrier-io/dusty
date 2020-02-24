#!/usr/bin/python3
# coding=utf-8

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
    URL tools
"""

import re

from collections import namedtuple


def parse_url(url):
    """ Parses URL into parts """
    parsed_url = re.search("".join([
        r"^\s*((?P<protocol>.*?)\:\/\/)?",
        r"((?P<username>.*?)(\:(?P<password>.*))?\@)?",
        r"((?P<hostname>.*?)(\:((?P<port>[0-9]+)))?)(?P<path>/.*?)?",
        r"(?P<query>\?.*?)?(?P<fragment>\#.*?)?\s*$"
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
        "username", "password", "raw"
    ])
    return result(
        protocol=protocol if protocol is not None else "",
        hostname=hostname if hostname is not None else "",
        port=port if port is not None else "",
        path=path if path is not None else "/",
        query=query[1:] if query is not None else "",
        fragment=fragment[1:] if fragment is not None else "",
        username=username if username is not None else "",
        password=password if password is not None else "",
        raw=url
    )


def get_port(parsed_url):
    """ Get port from parsed URL """
    if parsed_url.port:
        return parsed_url.port
    if parsed_url.protocol == "https":
        return "443"
    return "80"


def find_ip(url):
    """ Find IP address in string (code from dusty 1.0) """
    ip_pattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s')  # pylint: disable=W1401
    ip_value = re.findall(ip_pattern, url)
    return ip_value
