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
            path = item.find('Class').find('SourceLine').get('sourcefile')
            line = item.find('Class').find('SourceLine').find('Message').text

            str = ''
            for element in item.findall('SourceLine'):
                str += (element.find('Message').text + "\n\n")

            dupe_key = title + ' ' + issue_type + ' ' + category

            severity_level = SEVERITY_TYPE.get(int(severity), "")

            if dupe_key not in dupes:
                dupes[dupe_key] = Finding(title = title,
                                          tool = "spotbugs",
                                          active = False,
                                          verified = False,
                                          description = description,
                                          severity = severity_level,
                                          numerical_severity = severity,
                                          mitigation = False,
                                          impact = False,
                                          references = False,
                                          file_path = path,
                                          line = line,
                                          url = 'N/A',
                                          date = find_date,
                                          steps_to_reproduce = str,
                                          static_finding = True)
        self.items = dupes.values()
