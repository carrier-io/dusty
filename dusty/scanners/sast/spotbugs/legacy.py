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

__author__ = 'akaminski, arozumenko'

from dusty.tools import log as logging
import hashlib
import xml.etree.ElementTree
from xml.sax import saxutils
from dusty.tools import markdown


def sanitize(input):
    return saxutils.unescape(input).replace("<", "").replace(">", "")


class SpotbugsParser(object):
    def __init__(self, filename):
        logging.debug("Spotbugs parser initialization")

        dupes = dict()
        find_date = None

        data = xml.etree.ElementTree.parse(filename).getroot()
        for item in data.findall('BugInstance'):
            title = item.find('ShortMessage').text
            description = markdown.markdown_escape(item.find('LongMessage').text)
            category = item.get('category')
            issue_type = item.get('type')
            severity = item.get('priority')
            classname = item.find('Class').get('classname')
            filename = item.find('Class').find('SourceLine').get('sourcefile')
            file_path = item.find('Class').find('SourceLine').get('sourcepath')
            line = item.find('Class').find('SourceLine').find('Message').text
            steps_to_reproduce = ""
            details = data.find(f'.//BugPattern[@type="{issue_type}"]')
            for i, element in enumerate(item.findall('Method')):
                steps_to_reproduce += f"\n\nClassname: {classname}\n" \
                                      f"{element.find('Message').text}\n"
                try:
                    steps_to_reproduce += \
                                      f"{sanitize(item.findall('SourceLine')[i].find('Message').text)}"
                except:
                    pass

            if details is not None:
                description += f'\n\n Details: {markdown.html_to_text(details.find("Details").text)}'
            dupe_key = hashlib.md5(f'{title} {issue_type} {category}'.encode('utf-8')).hexdigest()
            if file_path:
                dupe_key += f' {file_path}'
            if filename:
                title += f' in {filename}'
            if dupe_key not in dupes:
                dupes[dupe_key] = {
                    "title": title,
                    "category": category,
                    "description": description,
                    "severity": int(severity),
                    "file_path": file_path if file_path else filename if filename else "",
                    "line": line,
                    "date": find_date,
                    "steps_to_reproduce": list()
                }
                dupes[dupe_key]['steps_to_reproduce'].append(f'<pre>{issue_type} issue {steps_to_reproduce}</pre>')
            else:
                dupes[dupe_key]['steps_to_reproduce'].append(f"<pre>{steps_to_reproduce}</pre>")

        self.items = dupes.values()

        logging.debug("Spotbugs output parsing done")
