#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,R0903

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
    Finding models
"""

from dusty.models.meta import MetaModel


class DastFinding(MetaModel):
    """
        DAST Finding

        - Fields:
        title - finding title (simple text)
        description - markdown-formatted (and escaped) item description

        - Common metadata:
        severity - finding severity level
        tool - scanner name
        endpoints - list of parsed endpoints (URLs)
        confidence - scanner confidence

        - DAST (legacy) metadata:
        legacy.images - screenshots for ReportPortal attachments

        - Metadata injected by processors:
        issue_hash - (legacy) issue hash string
        false_positive_finding - True if issue hash is in fpconfig
        information_finding - True if finding is filtered by min_severity_filter
    """

    def __init__(self, title, description):
        super().__init__()
        self.title = title
        self.description = description


class SastFinding(MetaModel):
    """
        SAST Finding

        - Fields:
        title - finding title (simple text)
        description - list of markdown-formatted (and escaped) item description chunks/steps/items

        - Common metadata:
        severity - finding severity level
        tool - scanner name
        endpoints - list of endpoints (filenames)
        confidence - scanner confidence

        - SAST (legacy) metadata:
        legacy.file - file name/path
        legacy.line - file line number
        legacy.cwe - CWE-ID

        - Metadata injected by processors:
        issue_hash - (legacy) issue hash string
        false_positive_finding - True if issue hash is in fpconfig
        information_finding - True if finding is filtered by min_severity_filter
    """

    def __init__(self, title, description):
        super().__init__()
        self.title = title
        self.description = description
