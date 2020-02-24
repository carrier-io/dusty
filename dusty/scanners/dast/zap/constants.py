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


ZAP_PATH = "/opt/zap/zap.jar"

ZAP_BLACKLISTED_RULES = [
    10095  # Backup File Disclosure
]

ZAP_SCAN_POCILICES = {
    "xss": [40012, 40014, 40016, 40017],
    "sqli": [40018, 40019, 40020, 40021, 40022]
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
