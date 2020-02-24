#!/usr/bin/python3
# coding=utf-8

#   Copyright 2019 getcarrier.io
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

"""
    Constants
"""


W3AF_OUTPUT_SECTION = """
#Configure reporting in order to generate an HTML report
output console, xml_file
output config xml_file
set output_file {output_file}
back
output config console
set verbose False
back
back
"""

W3AF_SEVERITIES = {
    'Information': 'Info',
    'Low': 'Low',
    'Medium': 'Medium',
    'High': 'High'
}
