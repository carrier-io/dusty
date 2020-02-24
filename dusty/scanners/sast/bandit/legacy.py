#!/usr/bin/python3
# coding=utf-8
# pylint: skip-file

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
    Code from Dusty 1.0
"""

__author__ = 'aaronweaver'
# Modified for Dusty by arozumenko

from datetime import datetime
import json


class BanditParser(object):
    def __init__(self, data):
        data = json.loads(data)
        dupes = dict()
        find_date = None
        if "generated_at" in data:
            find_date = datetime.strptime(data["generated_at"], '%Y-%m-%dT%H:%M:%SZ').strftime("%Y-%m-%d %H:%M:%S")

        for item in data["results"]:
            impact = ''
            findingdetail = ''

            title = "Test Name: " + item["test_name"] + " Test ID: " + item["test_id"]

            ###### Finding details information ######
            findingdetail += "Filename: " + item["filename"] + "\n"
            findingdetail += "Line number: " + str(item["line_number"]) + "\n"
            findingdetail += "Issue Confidence: " + item["issue_confidence"] + "\n\n"
            findingdetail += "Code:\n"
            findingdetail += item["code"] + "\n"

            sev = item["issue_severity"]
            mitigation = item["issue_text"]
            references = item["test_id"]

            dupe_key = title + item["filename"] + str(item["line_number"])

            if dupe_key not in dupes:
                dupes[dupe_key] = {
                    "title": title,
                    "description": findingdetail,
                    "severity": sev.title(),
                    "mitigation": mitigation,
                    "impact": impact,
                    "references": references,
                    "file_path": item["filename"],
                    "line": item["line_number"],
                    "date": find_date,
                    "bandit_id": item["test_id"]
                }
        self.items = dupes.values()
