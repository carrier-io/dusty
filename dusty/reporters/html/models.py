#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,R0903,R0913

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
    HTML report item models
"""


class HTMLReportMeta:
    """ HTML report meta item """

    def __init__(self, name, value):
        self.name = name
        self.value = value


class HTMLReportAlert:
    """ HTML report alert item """

    def __init__(self, type_, text):
        self.type = type_
        self.text = text


class HTMLReportFinding:
    """ HTML report finding item """

    def __init__(self, tool, title, severity, description, findings=None):
        self.tool = tool
        self.title = title
        self.severity = severity
        self.description = description
        self.findings = list()
        if findings:
            self.findings.extend(findings)


class HTMLReportError:
    """ HTML report error item """

    def __init__(self, tool, title, description):
        self.tool = tool
        self.title = title
        self.description = description
