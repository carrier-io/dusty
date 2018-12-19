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

from dusty.utils import execute, common_post_processing
from dusty.data_model.bandit.parser import BanditParser
from dusty.data_model.brakeman.parser import BrakemanParser
from dusty.data_model.spotbugs.parser import SpotbugsParser
from dusty.data_model.nodejsscan.parser import NodeJsScanParser


class SastyWrapper(object):
    @staticmethod
    def python(config):
        exec_cmd = "bandit -r /code --format json"
        res = execute(exec_cmd, cwd='/code')
        with open("/tmp/bandit.json", "w") as f:
            f.write(res[0].decode('utf-8', errors='ignore'))
        result = BanditParser("/tmp/bandit.json", "pybandit").items
        common_post_processing(config, result, "pybandit")
        return result

    @staticmethod
    def ruby(config):
        included_checks = ''
        exclude_checks = ''
        if config.get('include_checks', None):
            included_checks = f'-t {config.get("include_checks")} '
        if config.get('exclude_checks', None):
            exclude_checks = f'-x {config.get("exclude_checks")} '
        if config.get('excluded_files', None):
            exclude_checks = f'--skip-files {config.get("excluded_files")} '
        excluded_files = ''
        exec_cmd = f"brakeman {included_checks}{exclude_checks}--no-exit-on-warn --no-exit-on-error {excluded_files}" \
                   f"-o /tmp/brakeman.json /code"
        execute(exec_cmd, cwd='/code')
        result = BrakemanParser("/tmp/brakeman.json", "brakeman").items
        common_post_processing(config, result, "brakeman")
        return result
    
    @staticmethod
    def java(config):
        exec_cmd = "spotbugs -xml:withMessages -output /tmp/spotbugs.xml /code"
        res = execute(exec_cmd, cwd='/code')
        result = SpotbugsParser("/tmp/spotbugs.xml", "spotbugs").items
        common_post_processing(config, result, "spotbugs")
        return result

    @staticmethod
    def nodejs(config):
        exec_cmd = "nodejsscan -o nodejsscan -d /code"
        res = execute(exec_cmd, cwd='/tmp')
        result = NodeJsScanParser("/tmp/nodejsscan.json", "NodeJsScan").items
        common_post_processing(config, result, "NodeJsScan")
        return result
