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

NON_SCANNERS_CONFIG_KEYS = ['target_host', 'target_port', 'protocol', "/",
                            'reportportal', 'html_report', 'xml_report',
                            'safe_pipeline_mode', 'project_name', 'environment',
                            'test_type', 'junit_report', 'jira', 'emails',
                            'min_priority', 'code_path', 'composition_analysis']
SASTY_SCANNERS_CONFIG_KEYS = ['language', 'npm', 'retirejs', 'ptai', 'safety', 'scan_opts']
READ_THROUGH_ENV = ['target_host', 'target_port', 'protocol', 'project_name', 'environment']
CONFIG_ENV_KEY = "CARRIER_SCAN_CONFIG"
PATH_TO_CONFIG = "/tmp/scan-config.yaml"
PATH_TO_CODE = "/code"
SEVERITIES = {'Info': 4, 'Low': 3, 'Medium': 2,
              'High': 1, 'Critical': 0}
JIRA_SEVERITIES = {'Trivial': 4, 'Minor': 3, 'Major': 2,
                   'Critical': 1, 'Blocker': 0}
SEVERITIES_INVERSED = {v: k for k, v in SEVERITIES.items()}
SEVERITY_MAPPING = {
    'Critical': 'Blocker',
    'High': 'Critical',
    'Medium': 'Major',
    'Moderate': 'Minor',
    'Low': 'Minor',
    'Information': 'Trivial',
    'Info': 'Trivial',
    'Pattern': 'Trivial'
}
MAX_MESSAGE_LEN = 30000
FALSE_POSITIVE_CONFIG = '/tmp/false_positive.config'
W3AF_OUTPUT_SECTION = """#Configure reporting in order to generate an HTML report
output console, xml_file
output config xml_file
set output_file /tmp/w3af.xml
back
output config console
set verbose False
back
back"""

SEVERITY_TYPE = {
    0: 'Critical',
    1: 'High',
    2: 'Medium',
    3: 'Low'
}
NVD_URL = 'https://nvd.nist.gov/vuln/detail/'
JIRA_DESCRIPTION_MAX_SIZE = 61908
JIRA_OPENED_STATUSES = ['Open', 'In Progress']
MIN_PRIORITY = 'Major'
