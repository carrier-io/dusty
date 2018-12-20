__author__ = 'akaminski'
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
from dusty.data_model.canonical_model import DefaultModel as Finding


class NodeJsScanParser(object):
    def __init__(self, filename, test):
        dupes = dict()
        find_date = None

        with open(filename) as f:
            data = json.load(f)

        if len(data['good_finding']) > 0:
            for item in data['good_finding']:
                for value in data['good_finding'][item]:
                    title = value['title']
                    description = value['description']
                    file_path = value['path']
                    line = value['line']
                    steps_to_reproduce = value['lines']
                    dupe_key = item + ': ' + value['title'] + ' with file ' + value['filename']

                    if dupe_key not in dupes:
                        dupes[dupe_key] = Finding(title = title,
                                                  tool = "NodeJsScan",
                                                  active = False,
                                                  verified = False,
                                                  description = description,
                                                  severity = False,
                                                  numerical_severity = False,
                                                  mitigation = False,
                                                  impact = False,
                                                  references = False,
                                                  file_path = file_path,
                                                  line = line,
                                                  url = 'N/A',
                                                  date = find_date,
                                                  steps_to_reproduce = steps_to_reproduce.encode('utf-8'),
                                                  static_finding = True)
        if len(data['missing_sec_header']) > 0:
            for item in data['missing_sec_header']:
                for value in data['missing_sec_header'][item]:
                    description = value['description']
                    title = value['title']

                    dupe_key = item + ": " + title
                    if dupe_key not in dupes:
                        dupes[dupe_key] = Finding(title = title,
                                                  tool = "NodeJsScan",
                                                  active = False,
                                                  verified = False,
                                                  description = description,
                                                  severity = False,
                                                  numerical_severity = False,
                                                  mitigation = False,
                                                  impact = False,
                                                  references = False,
                                                  file_path = False,
                                                  line = False,
                                                  url = 'N/A',
                                                  date = find_date,
                                                  steps_to_reproduce = False,
                                                  static_finding = True)
        if len(data['sec_issues']) > 0:
            for item in data['sec_issues']:
                for value in data['sec_issues'][item]:
                    title = value['title']
                    description = value['description']
                    file_path = value['path']
                    line = value['line']
                    steps_to_reproduce = value['lines']
                    dupe_key = item + ': ' + value['title'] + ' with file ' + value['filename']

                    if dupe_key not in dupes:
                        dupes[dupe_key] = Finding(title = title,
                                                  tool = "NodeJsScan",
                                                  active = False,
                                                  verified = False,
                                                  description = description,
                                                  severity = False,
                                                  numerical_severity = False,
                                                  mitigation = False,
                                                  impact = False,
                                                  references = False,
                                                  file_path = file_path,
                                                  line = line,
                                                  url = 'N/A',
                                                  date = find_date,
                                                  steps_to_reproduce = steps_to_reproduce.encode('utf-8'),
                                                  static_finding = True)
        self.items = dupes.values()
