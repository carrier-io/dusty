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

from dusty.tools import markdown


__author__ = 'KarynaTaranova'


def get_dependencies(file_path, add_devdep=False):
    package_json = json.load(open(f'{file_path}/package.json'))
    deps = list(package_json.get('dependencies', {}).keys())
    if add_devdep:
        deps.extend(list(package_json.get('devDependencies', {}).keys()))
    return deps


class NpmScanParser(object):
    def __init__(self, data, deps):
        dupes = dict()
        find_date = None
        self.items = []
        data = json.loads(data)
        advisories = data.get('advisories')
        for action in data['actions']:
            module = action.get('module')
            if module in deps:
                EXTENDED_SEVERITIES = {
                    'Info': 4,
                    'Low': 3,
                    'Moderate': 2,
                    'High': 1,
                    'Critical': 0
                }
                unique_ids = {}
                tmp_values = {'file_paths': {}, 'descriptions': [], 'urls': [],
                              'references_list': [], 'cwes': []}
                severity = 'Info'
                format_str = '  \n*{}*:  {}\n  \n'
                for resolve in action.get('resolves'):
                    id = resolve.get('id')
                    if id not in unique_ids:
                        advisory = advisories.get(str(id))
                        unique_ids[id] = advisory.get('title')
                        tmp_values['file_paths'][unique_ids[id]] = []
                        current_severity = advisory.get('severity').title()
                        tmp_values['cwes'].append(advisory.get('cwe'))
                        if EXTENDED_SEVERITIES.get(current_severity) \
                                < EXTENDED_SEVERITIES.get(severity):
                            severity = current_severity
                        if advisory.get('url'):
                            tmp_values['urls'].append(format_str.format(unique_ids[id], markdown.markdown_escape(advisory.get('url'))))
                        if advisory.get('references'):
                            tmp_values['references_list'].append(
                                format_str.format(unique_ids[id], markdown.markdown_escape(advisory.get('references'))))
                            tmp_values['descriptions'].append(
                                format_str.format(unique_ids[id], markdown.markdown_escape(advisory.get('overview'))))
                    if id not in tmp_values['file_paths']:
                        tmp_values['file_paths'][unique_ids[id]].append('\n- {}'.format(resolve.get('path')))
                file_path = ''
                for key in tmp_values['file_paths']:
                    file_path = file_path + format_str.format(key, markdown.markdown_escape(',  '.join(tmp_values['file_paths'][key])))
                rehearsal_str = '\n'
                url = rehearsal_str.join(tmp_values['urls'])
                references = rehearsal_str.join(tmp_values['references_list'])
                description = rehearsal_str.join(tmp_values['descriptions'])
                swe = rehearsal_str.join(tmp_values['cwes'])
                title = ' '.join([action.get('action', ''),
                                  action.get('module', ''),
                                  action.get('target', '')])
                if title not in dupes:
                    dupes[title] = {
                        "title": title,
                        "description": description,
                        "severity": severity,
                        "file_path": file_path,
                        "url": url,
                        "date": find_date,
                        "references": references,
                        "cwe": swe
                    }
        self.items = dupes.values()
