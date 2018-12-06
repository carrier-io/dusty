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

from os import path
from junit_xml import TestSuite


class XUnitReport(object):
    def __init__(self, findings, config, report_path='/tmp/reports'):
        test_cases = []
        for finding in findings:
            test_cases.append(finding.junit_item())
        if not test_cases:
            return
        test_name = f'{config["project_name"]}-{config["environment"]}-{config["test_type"]}'
        report_name = path.join(report_path, f'TEST-{test_name}.xml')
        with open(report_name, 'w') as f:
            TestSuite.to_file(f, [TestSuite(test_name, test_cases)], prettyprint=False)
        print(f"Generated report:  <reports folder>/TEST-{test_name}.xml")