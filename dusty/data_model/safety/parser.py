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
from packaging import version
from dusty.data_model.canonical_model import DefaultModel as Finding


__author__ = 'KarynaTaranova'


class SafetyScanParser(object):
    def __init__(self, filename, test):
        dupes = dict()
        find_date = None
        self.items = []
        if not os.path.exists(filename):
            return
        data = json.load(open(filename))
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
                dupes[package] = Finding(title=title,
                                          tool=test,
                                          active=False,
                                          verified=False,
                                          description=description,
                                          severity='Medium',
                                          date=find_date,
                                          static_finding=True)
            else:
                prev_version = re.findall('to (.+) version', dupes[package].finding['title'])[0]
                if fixed_version != prev_version:
                    if version.parse(fixed_version) > version.parse(prev_version):
                        dupes[package].finding['title'] = title.replace(prev_version, fixed_version)
                        dupes[package].finding['description'] += '  \n  \n' + description
        self.items = dupes.values()


# SafetyScanParser('C:\\Users\\Karyna_Taranova\\AppData\\Local\\Temp\\reports\\test.json', 'safety')