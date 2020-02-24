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

import html


__author__ = 'akaminski, arozumenko'


class NodeJsScanParser(object):
    def __init__(self, data):
        dupes = dict()
        find_date = None
        self.items = []
        for sub_value in data:
            title = sub_value['title']
            description = sub_value['description']
            file_path = sub_value.get('path', '')
            line = sub_value.get('line', '')
            steps_to_reproduce = f'<pre>{html.escape(sub_value.get("lines", ""))}</pre>\n\n'
            dupe_key = sub_value['title'] + ' with file ' + sub_value.get('filename', '')
            if dupe_key not in dupes:
                steps_to_reproduce_list = list()
                steps_to_reproduce_list.append(re.sub(r'[^\x00-\x7f]', r'', steps_to_reproduce))
                dupes[dupe_key] = {
                    "title": dupe_key,
                    "description": description,
                    "severity": "Medium",
                    "file_path": file_path,
                    "line": line,
                    "date": find_date,
                    "steps_to_reproduce": steps_to_reproduce_list
                }
            else:
                dupes[dupe_key]['steps_to_reproduce'].append(re.sub(r'[^\x00-\x7f]', r'',
                                                                            steps_to_reproduce))
        self.items = dupes.values()
