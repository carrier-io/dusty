__author__ = 'akaminski, arozumenko'
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


import xml.etree.ElementTree
from dusty.data_model.canonical_model import DefaultModel as Finding
from dusty.constants import SEVERITY_TYPE


class SpotbugsParser(object):
    def __init__(self, filename, test):
        dupes = dict()
        find_date = None

        data = xml.etree.ElementTree.parse(filename).getroot()

        for item in data.findall('BugInstance'):
            title = item.find('ShortMessage').text
            description = item.find('LongMessage').text
            category = item.get('category')
            issue_type = item.get('type')
            severity = item.get('priority')
            filename = item.find('Class').find('SourceLine').get('sourcefile')
            file_path = item.find('Class').find('SourceLine').get('sourcepath')

            line = item.find('Class').find('SourceLine').find('Message').text

            steps_to_reproduce = ''
            for element in item.findall('SourceLine'):
                steps_to_reproduce += (element.find('Message').text + "\n\n")
            severity_level = SEVERITY_TYPE.get(int(severity), "")

            dupe_key = title + ' ' + issue_type + ' ' + category + ' ' + file_path
            if dupe_key not in dupes:
                dupes[dupe_key] = Finding(title=title + ' in ' + filename,
                                          tool="spotbugs", active=False,
                                          verified=False, description=description,
                                          severity=severity_level, numerical_severity=severity,
                                          mitigation=False, impact=False, references=False,
                                          file_path=file_path, line=line,
                                          url='N/A', date=find_date, steps_to_reproduce=steps_to_reproduce,
                                          static_finding=True)
            else:
                dupes[dupe_key].finding['steps_to_reproduce'] += steps_to_reproduce

        self.items = dupes.values()
