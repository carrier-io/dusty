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

import logging
import hashlib

from dusty.data_model.canonical_model import DefaultModel as Finding
from dusty.constants import SEVERITY_TYPE
from lxml import etree
from markdownify import markdownify as md
from xml.sax import saxutils


def sanitize(item):
    return saxutils.unescape(item).replace("<", "").replace(">", "")


class SpotbugsParser:
    def __init__(self, spotbugs_xml, test):
        self.spotbugs_xml = spotbugs_xml

        dupes = dict()
        find_date = None

        logging.debug("Spotbugs parser initialization")

        bugs_details = self.extract_bugs_details()

        context = etree.iterparse(self.spotbugs_xml, events=('end',), tag='BugInstance')

        for _, item in context:
            title = item.findtext('ShortMessage')
            description = item.findtext('LongMessage')
            category = item.get('category')
            issue_type = item.get('type')
            severity = item.get('priority')
            classname = item.find('Class').get('classname')
            filename = item.find('Class').find('SourceLine').get('sourcefile')
            file_path = item.find('Class').find('SourceLine').get('sourcepath')
            line = item.find('Class').find('SourceLine').findtext('Message')
            steps_to_reproduce = '\n'*2

            # TODO: rewrite this to avoid <IndexError: list index out of range> errors
            for i, element in enumerate(item.findall('Method')):
                steps_to_reproduce += f"Classname: {classname}\t{element.findtext('Message')}\t"
                try:
                    steps_to_reproduce += f"{sanitize(item.findall('SourceLine')[i].findtext('Message'))}"
                except IndexError:
                    pass

            details = bugs_details.get(issue_type)

            if details:
                description += f'\n\n Details: {md(details)}'

            severity_level = SEVERITY_TYPE.get(int(severity), "")

            dupe_key = hashlib.md5(f'{title} {issue_type} {category}'.encode('utf-8')).hexdigest()

            if file_path:
                dupe_key += f' {file_path}'

            if filename:
                title += f' in {filename}'

            if dupe_key not in dupes:
                dupes[dupe_key] = Finding(title=title, tool=category.lower().replace(" ", "_"),
                                          active=False, verified=False, description=description,
                                          severity=severity_level, numerical_severity=severity,
                                          mitigation=False, impact=False, references=False,
                                          file_path=file_path, line=line,
                                          url='N/A', date=find_date,
                                          steps_to_reproduce=f'<pre>{issue_type} issue {steps_to_reproduce}</pre>',
                                          static_finding=True)
            else:
                dupes[dupe_key].finding['steps_to_reproduce'].append(f"<pre>{steps_to_reproduce}</pre>")

            item.clear()
            while item.getprevious() is not None:
                del item.getparent()[0]

        del context

        self.items = dupes.values()

        logging.debug("Spotbugs output parsing done")

    def extract_bugs_details(self):
        context = etree.iterparse(self.spotbugs_xml, events=('end',), tag='BugPattern')

        details = dict()
        for _, item in context:
            details[item.get("type")] = item.findtext("Details")
            item.clear()
            while item.getprevious() is not None:
                del item.getparent()[0]

        del context
        return details
