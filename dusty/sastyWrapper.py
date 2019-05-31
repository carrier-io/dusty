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

from dusty import constants
from dusty.utils import execute, common_post_processing, ptai_post_processing, \
    run_in_parallel, get_dependencies
from dusty.data_model.bandit.parser import BanditParser
from dusty.data_model.brakeman.parser import BrakemanParser
from dusty.data_model.spotbugs.parser import SpotbugsParser
from dusty.data_model.nodejsscan.parser import NodeJsScanParser
from dusty.data_model.npm.parser import NpmScanParser
from dusty.data_model.retire.parser import RetireScanParser
from dusty.data_model.ptai.parser import PTAIScanParser
from dusty.data_model.safety.parser import SafetyScanParser
from dusty.data_model.dependency_check.parser import DependencyCheckParser
from dusty.data_model.gosec.parser import GosecOutputParser


class SastyWrapper(object):
    @staticmethod
    def get_code_path(config):
        return config.get("code_path", constants.PATH_TO_CODE)

    @staticmethod
    def get_code_source(config):
        return config.get("code_source", SastyWrapper.get_code_path(config))

    @staticmethod
    def execute_parallel(scan_fns, config, language):
        all_results = []
        params = []
        for fn in scan_fns:
            params.append((fn, config))
        results = run_in_parallel(params)
        for result in results:
            all_results.extend(result)
        filtered_result = common_post_processing(config, all_results, language, need_other_results=True)
        return filtered_result

    @staticmethod
    def extend_result(results, result):
        if results or isinstance(results, list):
            results.append(result)
        else:
            return result

    @staticmethod
    def python(config):
        scan_fns = [SastyWrapper.bandit]
        composition_analysis = config.get('composition_analysis', None)
        if composition_analysis:
            scan_fns.append(SastyWrapper.safety)
            if isinstance(composition_analysis, dict):
                config['files'] = composition_analysis.get('files', ['requirements.txt'])
        return SastyWrapper.execute_parallel(scan_fns, config, 'python')

    @staticmethod
    def bandit(config, results=None):
        exec_cmd = "bandit -r {} --format json".format(SastyWrapper.get_code_path(config))
        res = execute(exec_cmd, cwd=SastyWrapper.get_code_path(config))
        with open("/tmp/bandit.json", "w") as f:
            f.write(res[0].decode('utf-8', errors='ignore'))
        result = BanditParser("/tmp/bandit.json", "pybandit").items
        return SastyWrapper.extend_result(results, result)

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
        filtered_result = common_post_processing(config, result, "brakeman", need_other_results=True)
        return filtered_result

    @staticmethod
    def java(config):
        scan_fns = [SastyWrapper.spotbugs]
        composition_analysis = config.get('composition_analysis', None)
        if composition_analysis:
            scan_fns.append(SastyWrapper.dependency_check)
            config['comp_opts'] = ''
            config['comp_path'] = SastyWrapper.get_code_path(config)
            if isinstance(composition_analysis, dict):
                config['comp_opts'] = composition_analysis.get('scan_opts', '')
                config['comp_path'] = composition_analysis.get('scan_path', SastyWrapper.get_code_path(config))
        return SastyWrapper.execute_parallel(scan_fns, config, 'java')

    @staticmethod
    def spotbugs(config, results=None):
        exec_cmd = "spotbugs -xml:withMessages {} -output /tmp/spotbugs.xml {}" \
                   "".format(config.get("scan_opts", ""), SastyWrapper.get_code_path(config))
        execute(exec_cmd, cwd=SastyWrapper.get_code_path(config))
        result = SpotbugsParser("/tmp/spotbugs.xml", "spotbugs").items
        return SastyWrapper.extend_result(results, result)

    @staticmethod
    def nodejs(config):
        scan_fns = [SastyWrapper.nodejsscan]
        composition_analysis = config.get('composition_analysis', None)
        if composition_analysis:
            scan_fns.extend([SastyWrapper.npm, SastyWrapper.retirejs])
            config['add_devdep'] = composition_analysis.get('devdep', False) \
                if isinstance(composition_analysis, dict) else False
        return SastyWrapper.execute_parallel(scan_fns, config, 'nodejs')

    @staticmethod
    def npm(config, results=None):
        deps = get_dependencies(SastyWrapper.get_code_path(config), config.get('add_devdep'))
        exec_cmd = "npm audit --json"
        res = execute(exec_cmd, cwd=SastyWrapper.get_code_path(config))
        with open('/tmp/npm_audit.json', 'w') as npm_audit:
            print(res[0].decode(encoding='ascii', errors='ignore'), file=npm_audit)
        result = NpmScanParser("/tmp/npm_audit.json", "NpmScan", deps).items
        return SastyWrapper.extend_result(results, result)

    @staticmethod
    def retirejs(config, results=None):
        deps = get_dependencies(SastyWrapper.get_code_path(config), config.get('add_devdep'))
        exec_cmd = "retire --jspath={} --outputformat=json  " \
                   "--outputpath=/tmp/retirejs.json --includemeta --exitwith=0"\
            .format(SastyWrapper.get_code_path(config))
        res = execute(exec_cmd, cwd='/tmp')
        result = RetireScanParser("/tmp/retirejs.json", "RetireScan", deps).items
        return SastyWrapper.extend_result(results, result)

    @staticmethod
    def nodejsscan(config, results=None):
        exec_cmd = "nodejsscan -o nodejsscan -d {}".format(SastyWrapper.get_code_source(config))
        res = execute(exec_cmd, cwd='/tmp')
        result = NodeJsScanParser("/tmp/nodejsscan.json", "NodeJsScan").items
        return SastyWrapper.extend_result(results, result)

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
        return SastyWrapper.extend_result(results, result)

    @staticmethod
    def dependency_check(config, results=None):
        exec_cmd = 'dependency-check.sh -n -f JSON -o /tmp -s {} {}'.format(config['comp_path'], config['comp_opts'])
        execute(exec_cmd, cwd=SastyWrapper.get_code_path(config))
        result = DependencyCheckParser("/tmp/dependency-check-report.json", "dependency_check").items
        return SastyWrapper.extend_result(results, result)

    @staticmethod
    def golang(config):
        """ Golang SAST """
        scan_fns = [SastyWrapper.gosec]
        return SastyWrapper.execute_parallel(scan_fns, config, 'golang')

    @staticmethod
    def gosec(config, results=None):
        """ Golang Security Checker """
        exec_cmd = f"gosec -fmt=json ./..."
        cmd_output = execute(exec_cmd, cwd=SastyWrapper.get_code_path(config))
        result = GosecOutputParser(cmd_output, "gosec").items
        return SastyWrapper.extend_result(results, result)
