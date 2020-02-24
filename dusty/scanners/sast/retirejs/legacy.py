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
import requests
from bs4 import BeautifulSoup
from distutils.version import LooseVersion
from dusty.tools import markdown


__author__ = 'KarynaTaranova'


NVD_URL = 'https://nvd.nist.gov/vuln/detail/'
SEVERITIES = {
    'Info': 4,
    'Low': 3,
    'Medium': 2,
    'High': 1,
    'Critical': 0
}


def get_dependencies(file_path, add_devdep=False):
    package_json = json.load(open(f'{file_path}/package.json'))
    deps = list(package_json.get('dependencies', {}).keys())
    if add_devdep:
        deps.extend(list(package_json.get('devDependencies', {}).keys()))
    return deps


class RetireScanParser(object):
    def __init__(self, filename, deps):
        dupes = dict()
        find_date = None
        self.items = []
        if not os.path.exists(filename):
            return
        data = json.load(open(filename))['data']
        components_data = {}
        for file_results in data:
            file_path = file_results.get('file')
            for version_results in file_results.get('results'):
                component = version_results.get('component')
                if component in deps:
                    if component not in components_data:
                        components_data[component] = \
                            {'versions': set(), 'descriptions': {}, 'references': {},
                             'file_paths': {}, 'version_to_update': '0', 'severity': 'Info'}
                    components_data[component]['versions'].add(version_results.get('version'))
                    for vulnerability in version_results.get('vulnerabilities', []):
                        summary = vulnerability.get('identifiers').get('summary')
                        if summary not in components_data[component]['file_paths']:
                            components_data[component]['file_paths'][summary] = set()
                            components_data[component]['references'][summary] = set()
                        components_data[component]['file_paths'][summary].add(file_path)
                        for reference in vulnerability.get('info'):
                            if reference not in components_data[component]['references']:
                                components_data[component]['references'][summary].add(reference)
                                if NVD_URL in reference:
                                    url_text = requests.get(reference).text
                                    soup = BeautifulSoup(url_text, 'html.parser')
                                    recomendation = soup.find_all('a', {'id': 'showCPERanges'})
                                    if recomendation:
                                        ver_res = re.findall('versions up to \(excluding\)(.*)',
                                                             recomendation[0].attrs['data-range-description'])
                                        if ver_res:
                                            ver = ver_res[0].strip()
                                            if (LooseVersion(components_data[component]['version_to_update'])
                                                    < LooseVersion(ver)):
                                                components_data[component]['version_to_update'] = ver
                                    description = soup.find_all('p', {'data-testid': 'vuln-description'})
                                    if description:
                                        components_data[component]['descriptions'][summary] = description[0].text
                        cur_severity = vulnerability.get('severity').title()
                        if SEVERITIES.get(components_data[component]['severity']) \
                                > SEVERITIES.get(cur_severity):
                            components_data[component]['severity'] = cur_severity
        format_str = '  \n**{}**:  {}\n  \n'
        for key, value in components_data.items():
            title = 'Update {}'.format(key)
            if value.get('version_to_update') != '0':
                title += ' to version {}'.format(value.get('version_to_update'))
            severity = value.get('severity')
            description = '  \n'.join([format_str.format(markdown.markdown_escape(key), markdown.markdown_escape(val))
                                              for key, val in value.get('descriptions').items()])
            references = ''
            for ref_key, ref_val in value.get('references').items():
                _references = ','.join(['  \n- {}'.format(x) for x in ref_val]) + '  \n'
                references += format_str.format(markdown.markdown_escape(ref_key), markdown.markdown_escape(_references))
            file_path = ''
            for path_key, path_val in value.get('file_paths').items():
                _paths = ','.join(['  \n- {}'.format(x) for x in path_val]) + '  \n'
                file_path += format_str.format(markdown.markdown_escape(path_key), markdown.markdown_escape(_paths))
            dupes[title] = {
                "title": title,
                "description": description,
                "severity": severity,
                "file_path": file_path,
                "date": find_date,
                "references": references
            }
        self.items = dupes.values()
