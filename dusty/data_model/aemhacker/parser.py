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

import os
import re

from markdownify import markdownify as md
from dusty.data_model.canonical_model import DefaultModel as Finding


class AemOutputParser(object):
    """
    Parses aem-hacker output and populates finding list
    """

    def __init__(self, aem_hacker_output):
        tool = "AEM Hacker"
        severity = "Info"
        item_regex = re.compile(
            "^(\[\+\] New Finding!!!)$\s*Name: (?P<name>.*)$\s*Url: (?P<url>.*)$\s*Description: (?P<description>[\s\S]*?)\n\n",
            re.MULTILINE
        )

        self.items = list()
        for item in item_regex.finditer(aem_hacker_output):
            if os.environ.get("debug", False):
                print("Finding: name='{}', url='{}', description='{}'".format(
                    item.group('name'),
                    item.group('url'),
                    item.group('description')
                ))
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
            self.items.append(finding)
