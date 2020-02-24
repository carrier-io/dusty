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


LOG_FORMAT = "%(asctime)s - %(levelname)8s - %(name)s - %(message)s"
LOG_DATE_FORMAT = "%Y.%m.%d %H:%M:%S %Z"

DEFAULT_CONFIG_PATH = "config.yaml"
DEFAULT_CONFIG_ENV_KEY = "CARRIER_SCAN_CONFIG"

CONFIG_VERSION_KEY = "config_version"
CURRENT_CONFIG_VERSION = 2

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
