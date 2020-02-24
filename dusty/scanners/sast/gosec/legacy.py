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

import json

from collections import OrderedDict

from dusty.tools import markdown


class GosecOutputParser:
    """ Parses gosec output and populates finding list """

    def __init__(self, output):
        self.items = list()
        # Parse JSON from gosec stdout
        data = json.loads(output)
        # Populate findings
        all_items = OrderedDict()
        for item in data["Issues"]:
            # Prepare finding item
            title = f"{item['details']} - in {item['file']}"
            if title not in all_items:
                tool = "gosec"
                severity = item["severity"]
                file_path = item["file"]
                description = \
                    f"{markdown.markdown_escape(item['details'])}\n\n" \
                    f"**Rule ID**: {markdown.markdown_escape(item['rule_id'])}\n\n" \
                    f"**Confidence**: {markdown.markdown_escape(item['confidence'])}"
                steps_to_reproduce = list()
                all_items[title] = {
                    "title": title,
                    "severity": severity,
                    "file_path": file_path,
                    "description": description,
                    "steps_to_reproduce": steps_to_reproduce
                }
            # Fill steps to reproduce
            finding = all_items[title]
            finding['steps_to_reproduce'].append(
                f"<pre>" \
                f"Location: {item['file']}:{item['line']}\n" \
                f"Code:\n{item['code']}" \
                f"</pre>"
            )
        # Populate items
        for key in all_items:
            self.items.append(all_items[key])
