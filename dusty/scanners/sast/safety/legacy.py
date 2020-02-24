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
import os
import re
from packaging import version


__author__ = 'KarynaTaranova'


class SafetyScanParser(object):
    def __init__(self, data):
        dupes = dict()
        find_date = None
        self.items = []
        data = json.loads(data)
        for vulnerability in data:
            package = vulnerability[0]
            affected = vulnerability[1]
            installed = vulnerability[2]
            description = vulnerability[3]
            title = 'Update {} {}'.format(package, installed)
            version_to_update = affected.split(',')[-1].replace('<', '')
            fixed_version = 'latest' if '=' in version_to_update else version_to_update
            title += ' to {} version'.format(fixed_version)
            if package not in dupes:
                dupes[package] = {
                    "title": title,
                    "description": description
                }
            else:
                prev_version = re.findall('to (.+) version', dupes[package]['title'])[0]
                if fixed_version != prev_version:
                    if version.parse(fixed_version) > version.parse(prev_version):
                        dupes[package]['title'] = title.replace(prev_version, fixed_version)
                        dupes[package]['description'] += '  \n  \n' + description
        self.items = dupes.values()
