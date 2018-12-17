__author__ = 'aaronweaver'
# Modified for Dusty by akaminski

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

            #severity_type = {
            #    0: 'Critical',
            #    1: 'High',
            #    2: 'Medium',
            #    3: 'Low'
            #}
            severity_level = ''
            if int(severity) in SEVERITY_TYPE:
                severity_level = SEVERITY_TYPE[int(severity)]

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
