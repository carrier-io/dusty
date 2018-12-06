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

import argparse
import os
import yaml
import requests
from copy import deepcopy
from traceback import format_exc
from time import time

from dusty import constants
from dusty.drivers.rp.report_portal_writer import ReportPortalDataWriter
from dusty.dustyWrapper import DustyWrapper
from dusty.sastyWrapper import SastyWrapper
from dusty.drivers.html import HTMLReport
from dusty.drivers.xunit import XUnitReport

requests.packages.urllib3.disable_warnings()


def arg_parse(suites):
    parser = argparse.ArgumentParser(description='Executor for DAST scanner')
    parser.add_argument('-s', '--suite', type=str, help="specify test suite from (%s)" % ','.join(suites))
    return parser.parse_args()


def proxy_through_env(value):
    if isinstance(value, str) and value.startswith('$'):
        return os.environ.get(value.replace("$", ''))
    return value


def main():
    with open(constants.PATH_TO_CONFIG, "rb") as f:
        config = yaml.load(f.read())
    suites = list(config.keys())
    start_time = time()
    args = arg_parse(suites)
    rp_config = None
    rp_service = None
    html_report = None
    test_name = args.suite
    execution_config = config[test_name]
    generate_html = execution_config.get("html_report", False)
    generate_junit = execution_config.get("junit_report", False)
    if generate_html:
        print("We are going to generate HTML Report")
    if generate_junit:
        print("We are going to generate jUnit Report")
    execution_config['test_type'] = test_name
    for each in constants.READ_THROUGH_ENV:
        if each in execution_config:
            execution_config[each] = proxy_through_env(execution_config[each])
    global_results = []
    if execution_config.get("reportportal", None):
        rp_project = execution_config['reportportal'].get("rp_project_name", "Dusty")
        rp_launch_name = execution_config['reportportal'].get("rp_launch_name", test_name)
        rp_url = execution_config['reportportal'].get("rp_host")
        rp_token = execution_config['reportportal'].get("rp_token")
        if not (rp_launch_name and rp_project and rp_url and rp_token):
            print("ReportPortal configuration values missing, proceeding "
                  "without report portal integration ")
        else:
            rp_service = ReportPortalDataWriter(rp_url, rp_token, rp_project, rp_launch_name)
            launch_id = rp_service.start_test()
            rp_config = dict(rp_url=rp_url, rp_token=rp_token, rp_project=rp_project,
                             rp_launch_name=rp_launch_name, launch_id=launch_id)
    default_config = dict(host=execution_config.get('target_host', None),
                          port=execution_config.get('target_port', None),
                          protocol=execution_config.get('protocol', None),
                          project_name=execution_config.get('project_name', None),
                          environment=execution_config.get('environment', None),
                          test_type=execution_config.get('test_type', None),
                          rp_data_writer=rp_service,
                          rp_config=rp_config,
                          html_report=html_report)
    for each in execution_config:
        if each in constants.NON_SCANNERS_CONFIG_KEYS:
            continue
        config = deepcopy(default_config)
        if isinstance(execution_config[each], dict):
            for item in execution_config[each]:
                config[item] = execution_config[each][item]
        results = []
        if 'language' in each:
            try:
                results = getattr(SastyWrapper, execution_config[each])(config)
            except:
                print("Exception during %s Scanning" % execution_config[each])
                if os.environ.get("debug", False):
                    print(format_exc())
        else:
            try:
                results = getattr(DustyWrapper, each)(config)
            except:
                print("Exception during %s Scanning" % each)
                if os.environ.get("debug", False):
                    print(format_exc())
        if generate_html or generate_junit:
            global_results.extend(results)
    if rp_service:
        rp_service.finish_test()
    default_config['execution_time'] = int(time()-start_time)
    if generate_html:
        HTMLReport(global_results, default_config)
    if generate_junit:
        XUnitReport(global_results, default_config)


if __name__ == "__main__":
    main()

