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
import re
from dusty.data_model.canonical_model import DefaultModel as Finding


__author__ = 'akaminski, arozumenko'


class NodeJsScanParser(object):
    def __init__(self, filename, test):
        dupes = dict()
        find_date = None
        self.items = []
        if not os.path.exists(filename):
            return
        data = json.load(open(filename))
        for item in ['good_finding', 'sec_issues', 'missing_sec_header']:
            for key, value in data[item].items():
                title = value['title']
                description = value['description']
                file_path = value.get('path', None)
                line = value.get('line', None)
                steps_to_reproduce = f'<pre>{value.get("lines", "")}</pre>\n\n'
                dupe_key = key + ': ' + value['title'] + ' with file ' + value['filename']
                if dupe_key not in dupes:
                    dupes[dupe_key] = Finding(title=title,
                                              tool=test,
                                              active=False,
                                              verified=False,
                                              description=description,
                                              severity='Medium',
                                              file_path=file_path,
                                              line=line,
                                              url='N/A',
                                              date=find_date,
                                              steps_to_reproduce=re.sub(r'[^\x00-\x7f]', r'', steps_to_reproduce),
                                              static_finding=True)
                else:
                    dupes[dupe_key].finding['steps_to_reproduce'] += "\n\n"
                    dupes[dupe_key].finding['steps_to_reproduce'] += re.sub(r'[^\x00-\x7f]', r'', steps_to_reproduce)
        self.items = dupes.values()
