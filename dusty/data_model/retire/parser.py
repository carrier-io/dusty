#   Copyright 2018 getcarrier.io
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


import json
import os
import urllib
import re
from distutils.version import LooseVersion
from dusty import constants
from dusty.data_model.canonical_model import DefaultModel as Finding


__author__ = 'KarynaTaranova'


class RetireScanParser(object):
    def __init__(self, filename, test, devdeps):
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
                if component not in devdeps:
                    if component not in components_data:
                        components_data[component] = \
                            {'versions': set(), 'descriptions': {}, 'references': {},
                             'file_paths': {}, 'version_to_update': '0', 'severity': 'Info'}
                    components_data[component]['versions'].add(version_results.get('version'))
                    for vulnerability in version_results.get('vulnerabilities'):
                        summary = vulnerability.get('identifiers').get('summary')
                        if summary not in components_data[component]['file_paths']:
                            components_data[component]['file_paths'][summary] = set()
                            components_data[component]['references'][summary] = set()
                        components_data[component]['file_paths'][summary].add(file_path)
                        for reference in vulnerability.get('info'):
                            if reference not in components_data[component]['references']:
                                components_data[component]['references'][summary].add(reference)
                                if 'https://nvd.nist.gov/vuln/detail/' in reference:
                                    with urllib.request.urlopen(reference) as file:
                                        url_text = (file.read().decode('utf-8'))
                                    recomendation = re.findall(
                                        'data-range-description=\'(.*)\' data-range-cpe23shown', url_text)
                                    if recomendation:
                                        ver_res = re.findall('versions up to \(excluding\)(.*)', recomendation[0])
                                        if ver_res:
                                            ver = ver_res[0].strip()
                                            if (LooseVersion(components_data[component]['version_to_update'])
                                                    < LooseVersion(ver)):
                                                components_data[component]['version_to_update'] = ver
                                    description = re.findall('<p data-testid="vuln-description">(.*)</p>', url_text)
                                    if description:
                                        components_data[component]['descriptions'][summary] = description[0]
                        cur_severity = vulnerability.get('severity').title()
                        if constants.SEVERITIES.get(components_data[component]['severity']) \
                                > constants.SEVERITIES.get(cur_severity):
                            components_data[component]['severity'] = cur_severity
        format_str = '  \n**{}**:  {}\n  \n'
        for key, value in components_data.items():
            title = 'Update {}'.format(key)
            if value.get('version_to_update') != '0':
                title += ' to version {}'.format(value.get('version_to_update'))
            severity = value.get('severity')
            description = '  \n'.join([format_str.format(key, val)
                                              for key, val in value.get('descriptions').items()])
            references = ''
            for ref_key, ref_val in value.get('references').items():
                _references = ','.join(['  \n- {}'.format(x) for x in ref_val]) + '  \n'
                references += format_str.format(ref_key, _references)
            file_path = ''
            for path_key, path_val in value.get('file_paths').items():
                _paths = ','.join(['  \n- {}'.format(x) for x in path_val]) + '  \n'
                file_path += format_str.format(path_key, _paths)
            dupes[title] = Finding(title=title,
                                      tool=test,
                                      active=False,
                                      verified=False,
                                      description=description,
                                      severity=severity,
                                      file_path=file_path,
                                      line=' ',
                                      date=find_date,
                                      references=references,
                                      static_finding=True)
        self.items = dupes.values()
