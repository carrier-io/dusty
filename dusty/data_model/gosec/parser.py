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
    Gosec scanner output parser
"""

import json

from collections import OrderedDict
from dusty.data_model.canonical_model import DefaultModel as Finding


class GosecOutputParser:
    """ Parses gosec output and populates finding list """

    GOSEC_SEVERITY_MAPPING = {
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "UNDEFINED": "Info"
    }

    def __init__(self, output, _):
        self.items = list()
        # Parse JSON from gosec stdout
        data = json.loads(output[0].decode("utf-8"))
        # Populate findings
        all_items = OrderedDict()
        for item in data["Issues"]:
            # Prepare finding item
            title = f"{item['details']} - in {item['file']}"
            if title not in all_items:
                tool = "gosec"
                severity = GosecOutputParser.GOSEC_SEVERITY_MAPPING[item["severity"]]
                file_path = item["file"]
                description = \
                    f"{item['details']}\n" \
                    f"**Rule ID**: {item['rule_id']}\n" \
                    f"**Confidence**: {item['confidence']}"
                steps_to_reproduce = list()
                all_items[title] = Finding(
                    tool=tool, title=title,
                    severity=severity, numerical_severity=Finding.get_numerical_severity(severity),
                    file_path=file_path, description=description,
                    steps_to_reproduce=steps_to_reproduce,
                    active=False, url="N/A",
                    static_finding=True, verified=False,
                    mitigation=False, impact=False, references=False
                )
            # Fill steps to reproduce
            finding = all_items[title]
            finding.finding['steps_to_reproduce'].append(
                f"<pre>" \
                f"Location: {item['file']}:{item['line']}\n" \
                f"Code:\n{item['code']}" \
                f"</pre>"
            )
        # Populate items
        for key in all_items:
            self.items.append(all_items[key])
