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
from dusty.drivers.jira import JiraWrapper
from dusty.drivers.emails import EmailWrapper
from dusty.dustyWrapper import DustyWrapper
from dusty.sastyWrapper import SastyWrapper
from dusty.drivers.html import HTMLReport
from dusty.drivers.xunit import XUnitReport
from dusty.drivers.redis_file import RedisFile
from dusty.utils import send_emails

requests.packages.urllib3.disable_warnings()


def arg_parse(suites):
    parser = argparse.ArgumentParser(description='Executor for DAST scanner')
    parser.add_argument('-s', '--suite', type=str, help="specify test suite from (%s)" % ','.join(suites))
    return parser.parse_args()


def proxy_through_env(value):
    if isinstance(value, str) and value.startswith('$'):
        return os.environ.get(value.replace("$", ''))
    return value


def parse_jira_config(config):
    jira_url = proxy_through_env(config['jira'].get("url", None))
    jira_user = proxy_through_env(config['jira'].get("username", None))
    jira_pwd = proxy_through_env(config['jira'].get("password", None))
    jira_project = proxy_through_env(config['jira'].get("project", None))
    jira_assignee = proxy_through_env(config['jira'].get("assignee", None))
    jira_issue_type = proxy_through_env(config['jira'].get("issue_type", 'Bug'))
    jira_lables = proxy_through_env(config['jira'].get("labels", ''))
    jira_watchers = proxy_through_env(config['jira'].get("watchers", ''))
    jira_epic_key = proxy_through_env(config['jira'].get("epic_link", None))
    jira_fields = proxy_through_env(config['jira'].get("fields", None))
    if not (jira_url and jira_user and jira_pwd and jira_project and jira_assignee):
        print("Jira integration configuration is messed up , proceeding without Jira")
    else:
        return JiraWrapper(jira_url, jira_user, jira_pwd, jira_project,
                           jira_assignee, jira_issue_type, jira_lables,
                           jira_watchers, jira_epic_key, jira_fields)


def parse_email_config(config):
    emails_service = None
    emails_smtp_server = proxy_through_env(config['emails'].get('smtp_server', None))
    emails_port = proxy_through_env(config['emails'].get('port', None))
    emails_login = proxy_through_env(config['emails'].get('login', None))
    emails_password = proxy_through_env(config['emails'].get('password', None))
    emails_receivers_email_list = proxy_through_env(
        config['emails'].get('receivers_email_list', '')).split(', ')
    emails_subject = proxy_through_env(config['emails'].get('subject', None))
    emails_body = proxy_through_env(config['emails'].get('body', None))
    email_attachments = proxy_through_env(config['emails'].get('attachments', []))
    if email_attachments:
        email_attachments = email_attachments.split(',')
    constants.JIRA_OPENED_STATUSES.extend(proxy_through_env(
        config['emails'].get('open_states', '')).split(', '))
    if not (emails_smtp_server and emails_login and emails_password and emails_receivers_email_list):
        print("Emails integration configuration is messed up , proceeding without Emails")
    else:
        emails_service = EmailWrapper(emails_smtp_server, emails_login, emails_password, emails_port,
                                      emails_receivers_email_list, emails_subject, emails_body)
    return emails_service, email_attachments


def parse_rp_config(config, test_name, rp_service=None, launch_id=None, rp_config=None):
    rp_project = config['reportportal'].get("rp_project_name", "Dusty")
    rp_launch_name = config['reportportal'].get("rp_launch_name", test_name)
    rp_url = config['reportportal'].get("rp_host")
    rp_token = config['reportportal'].get("rp_token")
    if not (rp_launch_name and rp_project and rp_url and rp_token):
        print("ReportPortal configuration values missing, proceeding "
              "without report portal integration ")
    else:
        rp_service = ReportPortalDataWriter(rp_url, rp_token, rp_project, rp_launch_name)
        launch_id = rp_service.start_test()
        rp_config = dict(rp_url=rp_url, rp_token=rp_token, rp_project=rp_project,
                         rp_launch_name=rp_launch_name, launch_id=launch_id)
    return rp_service, launch_id, rp_config


def config_from_yaml():
    rp_service = None
    jira_service = None
    rp_config = None
    html_report = None
    email_service=None
    email_attachments = []
    if constants.CONFIG_ENV_KEY in os.environ.keys():
        config = yaml.load(os.environ.get(constants.CONFIG_ENV_KEY))
        print(f"Loaded configuration from ${constants.CONFIG_ENV_KEY}")
    else:
        path_to_config = os.environ.get('config_path', constants.PATH_TO_CONFIG)
        with open(path_to_config, "rb") as f:
            config = yaml.load(f.read())
            print(f"Loaded configuration from {path_to_config}")
    path_to_false_positive = os.environ.get('false_positive_path', constants.FALSE_POSITIVE_CONFIG)
    suites = list(config.keys())
    args = arg_parse(suites)
    test_name = args.suite
    execution_config = config[test_name]
    generate_html = execution_config.get("html_report", False)
    generate_junit = execution_config.get("junit_report", False)
    code_path = proxy_through_env(execution_config.get("code_path", constants.PATH_TO_CODE))
    if generate_html:
        print("We are going to generate HTML Report")
    if generate_junit:
        print("We are going to generate jUnit Report")
    execution_config['test_type'] = test_name
    for each in constants.READ_THROUGH_ENV:
        if each in execution_config:
            execution_config[each] = proxy_through_env(execution_config[each])
    if execution_config.get("reportportal", None):
        rp_service, launch_id, rp_config = parse_rp_config(execution_config, test_name)
    min_priority = proxy_through_env(
        execution_config.get("min_priority", constants.MIN_PRIORITY))
    if execution_config.get("jira", None):
        # basic_auth
        jira_service = parse_jira_config(execution_config)
    ptai_report_name = proxy_through_env(execution_config.get('ptai', {}).get('report_name', None))
    if execution_config.get('emails', None):
        email_service, email_attachments = parse_email_config(execution_config)
    default_config = dict(host=execution_config.get('target_host', None),
                          port=execution_config.get('target_port', None),
                          protocol=execution_config.get('protocol', None),
                          project_name=execution_config.get('project_name', None),
                          environment=execution_config.get('environment', None),
                          test_type=execution_config.get('test_type', None),
                          rp_data_writer=rp_service,
                          jira_service=jira_service,
                          min_priority=min_priority,
                          rp_config=rp_config,
                          generate_html=generate_html,
                          generate_junit=generate_junit,
                          html_report=html_report,
                          ptai_report_name=ptai_report_name,
                          code_path=code_path,
                          path_to_false_positive=path_to_false_positive,
                          email_service=email_service,
                          email_attachments=email_attachments,
                          composition_analysis=execution_config.get('composition_analysis', None))
    tests_config = {}
    for each in execution_config:
        if each in constants.NON_SCANNERS_CONFIG_KEYS:
            continue
        config = deepcopy(default_config)
        if isinstance(execution_config[each], dict):
            for item in execution_config[each]:
                config[item] = execution_config[each][item]
        if execution_config.get('language'):
            config['language'] = execution_config['language']
            config['scan_opts'] = execution_config.get('scan_opts', '')
        tests_config[each] = config
    return default_config, tests_config


def process_results(default_config, start_time, global_results=None, html_report_file=None, xml_report_file=None):
    created_jira_tickets = []
    attachments = []
    if default_config.get('rp_data_writer', None):
        default_config['rp_data_writer'].finish_test()
    default_config['execution_time'] = int(time()-start_time)
    if default_config.get('generate_html', None):
        html_report_file = HTMLReport(sorted(global_results, key=lambda item: item.severity),
                                      default_config).report_name
    if default_config.get('generate_junit', None):
        xml_report_file = XUnitReport(global_results, default_config).report_name
    if os.environ.get("redis_connection"):
        RedisFile(os.environ.get("redis_connection"), html_report_file, xml_report_file)
    if default_config.get('jira_service', None):
        created_jira_tickets = default_config['jira_service'].get_created_tickets()
    if default_config.get('email_service', None):
        if html_report_file:
            attachments.append(html_report_file)
        for item in default_config.get('email_attachments', None):
            attachments.append('/attachments/' + item.strip())
        #TODO: Rework sending of emails to be not tiedly coupled with Jira
        send_emails(default_config['email_service'], True, jira_tickets_info=created_jira_tickets,
                    attachments=attachments)


def main():
    start_time = time()
    global_results = []
    default_config, test_configs = config_from_yaml()
    for key in test_configs:
        results = []
        config = test_configs[key]
        if key in constants.SASTY_SCANNERS_CONFIG_KEYS:
            if key == "scan_opts":
                continue
            attr_name = config[key] if 'language' in key else key
            try:
                results = getattr(SastyWrapper, attr_name)(config)
            except:
                print("Exception during %s Scanning" % attr_name)
                if os.environ.get("debug", False):
                    print(format_exc())
        else:
            try:
                results = getattr(DustyWrapper, key)(config)
            except:
                print("Exception during %s Scanning" % key)
                if os.environ.get("debug", False):
                    print(format_exc())
        if default_config.get('generate_html', None) or default_config.get('generate_junit', None):
            global_results.extend(results)
    process_results(default_config, start_time, global_results)


if __name__ == "__main__":
    main()

