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
    Status tools
"""

import time

from dusty.tools import log


def wait_for_completion(condition, status, message, interval=10):
    """ Watch progress """
    current_status = status()
    log.get_outer_logger().info(message, current_status)
    while condition():
        time.sleep(interval)
        next_status = status()
        if next_status != current_status:
            log.get_outer_logger().info(message, next_status)
        current_status = next_status
