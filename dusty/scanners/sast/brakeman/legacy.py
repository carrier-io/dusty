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


class BrakemanParser(object):
    def __init__(self, data):
        data = json.loads(data)
        dupes = dict()
        find_date = data['scan_info']['start_time']

        for item in data["warnings"]:
            dupe_key = f"{item['warning_type']} in {item['file']}"

            if dupe_key not in dupes:
                dupes[dupe_key] = {
                    "title": dupe_key,
                    "description": item['message'],
                    "scanner_confidence": item['confidence'],
                    "severity": item['confidence'],
                    "references": item['link'],
                    "file_path": item["file"],
                    "line": item["line"],
                    "date": find_date
                }
        self.items = dupes.values()
