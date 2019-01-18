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
from dusty import constants
from dusty.data_model.canonical_model import DefaultModel as Finding


__author__ = 'KarynaTaranova'


class NpmScanParser(object):
    def __init__(self, filename, test, devdeps):
        dupes = dict()
        find_date = None
        self.items = []
        if not os.path.exists(filename):
            return
        data = json.load(open(filename))
        advisories = data.get('advisories')
        for action in data['actions']:
            module = action.get('module')
            if module not in devdeps:
                title = ' '.join([action.get('action', ''),
                                  action.get('module', ''),
                                  action.get('target', '')])
                EXTENDED_SEVERITIES = constants.SEVERITIES.copy()
                EXTENDED_SEVERITIES['Moderate'] = 2
                unique_ids = {}
                tmp_values = {'file_paths': {}, 'descriptions': [], 'urls': [],
                              'references_list': [], 'cwes': []}
                severity = 'Info'
                format_str = '  \n**{}**:  {}\n  \n'
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
                            tmp_values['urls'].append(format_str.format(unique_ids[id], advisory.get('url')))
                        if advisory.get('references'):
                            tmp_values['references_list'].append(
                                format_str.format(unique_ids[id], advisory.get('references')))
                            tmp_values['descriptions'].append(
                                format_str.format(unique_ids[id], advisory.get('overview')))
                    if id not in tmp_values['file_paths']:
                        tmp_values['file_paths'][unique_ids[id]].append('\n- {}'.format(resolve.get('path')))
                file_path = ''
                for key in tmp_values['file_paths']:
                    file_path = file_path + format_str.format(key, ',  '.join(tmp_values['file_paths'][key]))
                rehearsal_str = ',  \n'
                url = rehearsal_str.join(tmp_values['urls'])
                references = rehearsal_str.join(tmp_values['references_list'])
                description = rehearsal_str.join(tmp_values['descriptions'])
                swe = rehearsal_str.join(tmp_values['cwes'])
                if title not in dupes:
                    dupes[title] = Finding(title=title,
                                              tool=test,
                                              active=False,
                                              verified=False,
                                              description=description,
                                              severity=severity,
                                              file_path=file_path,
                                              line=' ',
                                              url=url,
                                              date=find_date,
                                              references=references,
                                              cwe=swe,
                                              static_finding=True)
        self.items = dupes.values()
