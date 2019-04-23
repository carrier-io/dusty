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
                            'test_type', 'junit_report', 'jira', 'jira_mapping', 'emails',
                            'min_priority', 'code_path', 'composition_analysis', 'influx',
                            'code_source']
SASTY_SCANNERS_CONFIG_KEYS = ['language', 'npm', 'retirejs', 'ptai', 'safety', 'scan_opts']
READ_THROUGH_ENV = ['target_host', 'target_port', 'protocol', 'project_name', 'environment']
CONFIG_ENV_KEY = "CARRIER_SCAN_CONFIG"
PATH_TO_CONFIG = "/tmp/scan-config.yaml"
PATH_TO_CODE = "/code"
SEVERITIES = {
    'Info': 4,
    'Low': 3,
    'Medium': 2,
    'High': 1,
    'Critical': 0
}
JIRA_SEVERITIES = {
    'Trivial': 4,
    'Minor': 3,
    'Medium': 2,
    'Major': 1,
    'Critical': 0,
    'Blocker': 0
}
JIRA_ALTERNATIVES = {
    'Trivial': ['Low', 'Minor'],
    'Minor': ['Low', 'Medium'],
    'Medium': ['Major'],
    'Major': ['High', 'Critical'],
    'Critical': ['Very High', 'Blocker'],
    'Blocker': ['Very High', 'Critical']
}
SEVERITIES_INVERSED = {v: k for k, v in SEVERITIES.items()}
SEVERITY_MAPPING = {
    'Critical': 'Critical',
    'High': 'Major',
    'Medium': 'Medium',
    'Moderate': 'Medium',
    'Low': 'Minor',
    'Information': 'Trivial',
    'Info': 'Trivial',
    'Pattern': 'Trivial'
}
QUALYS_SEVERITIES = {
    1: 'Info',
    2: 'Low',
    3: 'Medium',
    4: 'High',
    5: 'Critical'
}
ZAP_SEVERITIES = {
    "0": "Info",
    "1": "Low",
    "2": "Medium",
    "3": "High"
}
ZAP_CONFIDENCES = {
    "0": "False Positive",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "User Confirmed"
}
ZAP_BLACKLISTED_RULES = [
    10095  # Backup File Disclosure
]
ZAP_SCAN_POCILICES = {
    "xss": [40012, 40014, 40016, 40017],
    "sqli": [40018, 40019, 40020, 40021, 40022]
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
# This is jira.text.field.character.limit default value
JIRA_COMMENT_MAX_SIZE = 32767
JIRA_OPENED_STATUSES = ['Open', 'In Progress']
MIN_PRIORITY = 'Major'

JIRA_FIELD_USE_DEFAULT_VALUE = '!default'
JIRA_FIELD_DO_NOT_USE_VALUE = '!remove'

PTAI_DEFAULT_FILTERED_STATUSES = ['discarded', 'suspected']
QUALYS_STATUS_CHECK_INTERVAL = 60
QUALYS_MAX_STATUS_CHECK_ERRORS = 7
