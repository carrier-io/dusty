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

import json
from dusty import constants
from dusty.utils import execute, common_post_processing, ptai_post_processing, run_in_parallel
from dusty.data_model.bandit.parser import BanditParser
from dusty.data_model.brakeman.parser import BrakemanParser
from dusty.data_model.spotbugs.parser import SpotbugsParser
from dusty.data_model.nodejsscan.parser import NodeJsScanParser
from dusty.data_model.npm.parser import NpmScanParser
from dusty.data_model.retire.parser import RetireScanParser
from dusty.data_model.ptai.parser import PTAIScanParser
from dusty.data_model.safety.parser import SafetyScanParser


class SastyWrapper(object):
    @staticmethod
    def get_code_path(config):
        return config.get("code_path", constants.PATH_TO_CODE)

    @staticmethod
    def python(config):
        scan_fns = [SastyWrapper.bandit]
        all_results = []
        composition_analysis = config.get('composition_analysis', None)
        if composition_analysis:
            scan_fns.append(SastyWrapper.safety)
            if isinstance(composition_analysis, dict):
                config['files'] = composition_analysis.get('files', ['requirements.txt'])
        params = []
        for fn in scan_fns:
            params.append((fn, config))

        results = run_in_parallel(params)
        for result in results:
            all_results.extend(result)
        return all_results

    @staticmethod
    def bandit(config, results=None):
        exec_cmd = "bandit -r {} --format json".format(SastyWrapper.get_code_path(config))
        res = execute(exec_cmd, cwd=SastyWrapper.get_code_path(config))
        with open("/tmp/bandit.json", "w") as f:
            f.write(res[0].decode('utf-8', errors='ignore'))
        result = BanditParser("/tmp/bandit.json", "pybandit").items
        filtered_result = common_post_processing(config, result, "pybandit")
        if results or isinstance(results, list):
            results.append(filtered_result)
        else:
            return filtered_result

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
                   f"-o /tmp/brakeman.json " + SastyWrapper.get_code_path(config)
        execute(exec_cmd, cwd=SastyWrapper.get_code_path(config))
        result = BrakemanParser("/tmp/brakeman.json", "brakeman").items
        filtered_result = common_post_processing(config, result, "brakeman")
        return filtered_result

    @staticmethod
    def java(config):
        exec_cmd = "spotbugs -xml:withMessages {} -output /tmp/spotbugs.xml {}" \
                   "".format(config.get("scan_opts", ""), SastyWrapper.get_code_path(config))
        execute(exec_cmd, cwd=SastyWrapper.get_code_path(config))
        result = SpotbugsParser("/tmp/spotbugs.xml", "spotbugs").items
        filtered_result = common_post_processing(config, result, "spotbugs")
        return filtered_result

    @staticmethod
    def nodejs(config):
        scan_fns = [SastyWrapper.nodejsscan]
        composition_analysis = config.get('composition_analysis', None)
        if composition_analysis:
            scan_fns.extend([SastyWrapper.npm, SastyWrapper.retirejs])
            if isinstance(composition_analysis, bool):
                config['devdep'] = composition_analysis
            elif isinstance(composition_analysis, dict):
                config['devdep'] = composition_analysis.get('devdep', True)
        params = []
        for fn in scan_fns:
            params.append((fn, config))
        all_results = []
        results = run_in_parallel(params)
        for result in results:
            all_results.extend(result)
        return all_results

    @staticmethod
    def npm(config, results=None):
        devdeps = [] if config.get('devdep') \
            else json.load(open('{}/package.json'.format(SastyWrapper.get_code_path(config)))) \
            .get('devDependencies', {}).keys()
        exec_cmd = "npm audit --json"
        res = execute(exec_cmd, cwd=SastyWrapper.get_code_path(config))
        with open('/tmp/npm_audit.json', 'w') as npm_audit:
            print(res[0].decode(encoding='ascii', errors='ignore'), file=npm_audit)
        result = NpmScanParser("/tmp/npm_audit.json", "NpmScan", devdeps).items
        filtered_result = common_post_processing(config, result, "NpmScan")
        if results or isinstance(results, list):
            results.append(filtered_result)
        else:
            return filtered_result

    @staticmethod
    def retirejs(config, results=None):
        devdeps = [] if config.get('devdep') \
            else json.load(open('{}/package.json'.format(SastyWrapper.get_code_path(config))))\
            .get('devDependencies', {}).keys()
        exec_cmd = "retire --jspath={} --outputformat=json  " \
                   "--outputpath=/tmp/retirejs.json --includemeta --exitwith=0"\
            .format(SastyWrapper.get_code_path(config))
        res = execute(exec_cmd, cwd='/tmp')
        result = RetireScanParser("/tmp/retirejs.json", "RetireScan", devdeps).items
        filtered_result = common_post_processing(config, result, "RetireScan")
        if results or isinstance(results, list):
            results.append(filtered_result)
        else:
            return filtered_result

    @staticmethod
    def nodejsscan(config, results=None):
        exec_cmd = "nodejsscan -o nodejsscan -d {}".format(SastyWrapper.get_code_path(config))
        res = execute(exec_cmd, cwd='/tmp')
        result = NodeJsScanParser("/tmp/nodejsscan.json", "NodeJsScan").items
        filtered_result = common_post_processing(config, result, "NodeJsScan")
        if results or isinstance(results, list):
            results.append(filtered_result)
        else:
            return filtered_result

    @staticmethod
    def ptai(config):
        file_path = '/tmp/reports/' + config['ptai_report_name']
        filtered_statuses = config.get('filtered_statuses', constants.PTAI_DEFAULT_FILTERED_STATUSES)
        if isinstance(filtered_statuses, str):
            filtered_statuses = [item.strip() for item in filtered_statuses.split(",")]
        result = PTAIScanParser(file_path, filtered_statuses).items
        filtered_result = ptai_post_processing(config, result)
        return filtered_result

    @staticmethod
    def safety(config, results=None):
        params_str = ''
        for file_path in config.get('files', []):
            params_str += '-r {} '.format(file_path)
        exec_cmd = "safety check {}--full-report --json".format(params_str)
        res = execute(exec_cmd, cwd=SastyWrapper.get_code_path(config))
        with open('/tmp/safety_report.json', 'w') as safety_audit:
            print(res[0].decode(encoding='ascii', errors='ignore'), file=safety_audit)
        result = SafetyScanParser("/tmp/safety_report.json", "SafetyScan").items
        filtered_result = common_post_processing(config, result, "SafetyScan")
        if results or isinstance(results, list):
            results.append(filtered_result)
        else:
            return filtered_result
