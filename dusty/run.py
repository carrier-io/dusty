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


def main():
    path_to_config = os.environ.get('config_path', constants.PATH_TO_CONFIG)
    path_to_false_positive = os.environ.get('false_positive_path', constants.FALSE_POSITIVE_CONFIG)
    with open(path_to_config, "rb") as f:
        config = yaml.load(f.read())
    suites = list(config.keys())
    start_time = time()
    args = arg_parse(suites)
    rp_config = None
    rp_service = None
    jira_service = None
    emails_service = None
    html_report = None
    html_report_file = None
    xml_report_file = None
    email_attachments = []
    created_jira_tickets = []
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
    min_priority = proxy_through_env(
        execution_config.get("min_priority", constants.MIN_PRIORITY))
    if execution_config.get("jira", None):
        # basic_auth
        jira_url = proxy_through_env(execution_config['jira'].get("url", None))
        jira_user = proxy_through_env(execution_config['jira'].get("username", None))
        jira_pwd = proxy_through_env(execution_config['jira'].get("password", None))
        jira_project = proxy_through_env(execution_config['jira'].get("project", None))
        jira_assignee = proxy_through_env(execution_config['jira'].get("assignee", None))
        jira_issue_type = proxy_through_env(execution_config['jira'].get("issue_type", 'Bug'))
        jira_lables = proxy_through_env(execution_config['jira'].get("labels", ''))
        jira_watchers = proxy_through_env(execution_config['jira'].get("watchers", ''))
        jira_epic_key = proxy_through_env(execution_config['jira'].get("epic_link", None))
        jira_fields = proxy_through_env(execution_config['jira'].get("fields", None))
        if not (jira_url and jira_user and jira_pwd and jira_project and jira_assignee):
            print("Jira integration configuration is messed up , proceeding without Jira")
        else:
            jira_service = JiraWrapper(jira_url, jira_user, jira_pwd, jira_project,
                                       jira_assignee, jira_issue_type, jira_lables,
                                       jira_watchers, jira_epic_key, jira_fields)
    ptai_report_name = proxy_through_env(execution_config.get('ptai', {}).get('report_name', None))
    if execution_config.get('emails', None):
        emails_smtp_server = proxy_through_env(execution_config['emails'].get('smtp_server', None))
        emails_port = proxy_through_env(execution_config['emails'].get('port', None))
        emails_login = proxy_through_env(execution_config['emails'].get('login', None))
        emails_password = proxy_through_env(execution_config['emails'].get('password', None))
        emails_receivers_email_list = proxy_through_env(
            execution_config['emails'].get('receivers_email_list', '')).split(', ')
        emails_subject = proxy_through_env(execution_config['emails'].get('subject', None))
        emails_body = proxy_through_env(execution_config['emails'].get('body', None))
        email_attachments = proxy_through_env(execution_config['emails'].get('attachments', []))
        if email_attachments:
            email_attachments = email_attachments.split(',')
        constants.JIRA_OPENED_STATUSES.extend(proxy_through_env(
            execution_config['emails'].get('open_states', '')).split(', '))
        if not (emails_smtp_server and emails_login and emails_password and emails_receivers_email_list):
            print("Emails integration configuration is messed up , proceeding without Emails")
        else:
            emails_service = EmailWrapper(emails_smtp_server, emails_login, emails_password, emails_port,
                                          emails_receivers_email_list, emails_subject, emails_body)
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
                          html_report=html_report,
                          ptai_report_name=ptai_report_name,
                          code_path=code_path,
                          path_to_false_positive=path_to_false_positive,
                          composition_analysis=execution_config.get('composition_analysis', None))
    for each in execution_config:
        if each in constants.NON_SCANNERS_CONFIG_KEYS:
            continue
        config = deepcopy(default_config)
        if isinstance(execution_config[each], dict):
            for item in execution_config[each]:
                config[item] = execution_config[each][item]
        results = []
        if each in constants.SASTY_SCANNERS_CONFIG_KEYS:
            attr_name = execution_config[each] if 'language' in each else each
            try:
                results = getattr(SastyWrapper, attr_name)(config)
            except:
                print("Exception during %s Scanning" % attr_name)
                if os.environ.get("debug", False):
                    print(format_exc())
        else:
            try:
                results = getattr(DustyWrapper, each)(config)
            except:
                print("Exception during %s Scanning" % each)
                if os.environ.get("debug", False):
                    print(format_exc())
        #TODO: created Jira Tickets are overwrittem by every loop.
        created_jira_tickets = []
        if config['jira_service']:
            created_jira_tickets = config['jira_service'].get_created_tickets()
        if generate_html or generate_junit:
            global_results.extend(results)
    if rp_service:
        rp_service.finish_test()
    default_config['execution_time'] = int(time()-start_time)
    if generate_html:
        html_report_file = HTMLReport(global_results, default_config).report_name
    if generate_junit:
        xml_report_file = XUnitReport(global_results, default_config).report_name
    if os.environ.get("redis_connection"):
        RedisFile(os.environ.get("redis_connection"), html_report_file, xml_report_file)
    if emails_service:
        attachments = []
        if execution_config['emails'].get('attach_html_report', False):
            attachments.append(html_report_file)
        for item in email_attachments:
            attachments.append('/attachments/' + item.strip())
        send_emails(emails_service, bool(jira_service),
                    jira_tickets_info=created_jira_tickets if jira_service else [],
                    attachments=attachments)


if __name__ == "__main__":
    main()

