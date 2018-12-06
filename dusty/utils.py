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

import re
import os
from subprocess import Popen, PIPE

from dusty import constants


def report_to_rp(config, result, issue_name):
    if config.get("rp_config"):
        rp_data_writer = config['rp_data_writer']
        rp_data_writer.start_test_item(issue=issue_name, tags=[], description=f"Results of {issue_name} scan",
                                       item_type="SUITE")
        for item in result:
            item.rp_item(rp_data_writer)
        rp_data_writer.finish_test_item()


def execute(exec_cmd, cwd='/tmp', communicate=True):
    print(f'Running: {exec_cmd}')
    proc = Popen(exec_cmd.split(" "), cwd=cwd, stdout=PIPE, stderr=PIPE)
    if communicate:
        res = proc.communicate()
        print("Done")
        if os.environ.get("debug", False):
            print(f"stdout: {res[0]}")
            print(f"stderr: {res[1]}")
        return res
    else:
        return proc


def find_ip(str):
    ip_pattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s')
    ip = re.findall(ip_pattern, str)
    return ip


def process_false_positives(results):
    false_positives = []
    if os.path.exists(constants.FALSE_POSITIVE_CONFIG):
        with open(constants.FALSE_POSITIVE_CONFIG, 'r') as f:
            for line in f.readlines():
                if line.strip():
                    false_positives.append(line.strip())
    if not false_positives:
        return results
    to_remove = []
    for index in range(len(results)):
        if results[index].finding['title'] in false_positives:
            to_remove.append(results[index])
    for _ in to_remove:
        results.pop(results.index(_))
    return results
