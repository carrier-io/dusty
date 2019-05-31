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
import re
import yaml
import requests
import logging
from copy import deepcopy
from traceback import format_exc
from time import time

from dusty import constants
from dusty.drivers.rp.report_portal_writer import launch_reportportal_service
from dusty.drivers.jira import JiraWrapper
from dusty.drivers.emails import EmailWrapper
from dusty.dustyWrapper import DustyWrapper
from dusty.sastyWrapper import SastyWrapper
from dusty.drivers.html import HTMLReport
from dusty.drivers.xunit import XUnitReport
from dusty.drivers.redis_file import RedisFile
from dusty.drivers.influx import InfluxReport
from dusty.drivers.loki import enable_loki_logging
from dusty.utils import send_emails, common_post_processing, prepare_jira_mapping, flush_logs

requests.packages.urllib3.disable_warnings()


def proxy_through_env(value):
    if isinstance(value, str) and value.startswith('$'):
        return os.environ.get(value.replace("$", ''))

    return value


def parse_args():
    args = None

    parser = argparse.ArgumentParser(prog='dusty', description="Security Scanning Orchestration")

    parser.add_argument("-c", "--config", type=str, help=f"Scan config file path [{constants.PATH_TO_CONFIG}]",
                        default=os.environ.get("config_path", constants.PATH_TO_CONFIG))
    parser.add_argument("--fp-config", type=str, help=f"False positive config file path [{constants.PATH_TO_CONFIG}]",
                        default=os.environ.get("false_positive_path", constants.FALSE_POSITIVE_CONFIG), required=False)
    parser.add_argument("--config-data", type=str,
                        help="Config data provided as a string. "
                             "This option will overwrite the config file if specified",
                        default=os.environ.get(constants.CONFIG_ENV_KEY, None), required=False)
    parser.add_argument("-s", "--suite", type=str, help="Suite from the config file to execute", required=True)
    parser.add_argument("-d", "--debug", help="Debug mode", default=os.environ.get("debug", False), action="store_true")
    try:
        args, _ = parser.parse_known_args()
        if args.suite not in list_of_available_suites(args):
            raise NameError()
        return args
    except (argparse.ArgumentError, argparse.ArgumentTypeError):
        parser.print_help()
        exit(0)
    except NameError:
        parser.print_help()
        print(f"Available Suites are: {list_of_available_suites(args)}")
        exit(0)


def variable_substitution(obj):
    """ Allows to use environmental variables inside YAML/JSON config """
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            obj[variable_substitution(key)] = \
                variable_substitution(obj.pop(key))

    if isinstance(obj, list):
        for index, item in enumerate(obj):
            obj[index] = variable_substitution(item)

    if isinstance(obj, str) and re.match(r"^\$[a-zA-Z_][a-zA-Z0-9_]*$", obj) \
            and obj[1:] in os.environ:
        return os.environ[obj[1:]]

    return obj


def parse_jira_config(config):
    jira_config = config.get("jira")

    if not jira_config:
        return None

    jira_url = proxy_through_env(jira_config.get("url", None))
    jira_user = proxy_through_env(jira_config.get("username", None))
    jira_pwd = proxy_through_env(jira_config.get("password", None))
    jira_project = proxy_through_env(jira_config.get("project", None))
    jira_fields = {}

    for field_name, field_value in proxy_through_env(jira_config.get("fields", {})).items():
        value = proxy_through_env(field_value)
        if value:
            jira_fields[field_name] = value

    # tmp
    deprecated_fields = ["assignee", "issue_type", "labels", "watchers", "epic_link"]
    if any(deprecated_field in deprecated_fields for deprecated_field in jira_config):
        logging.warning('WARNING: using deprecated config, please update!')
        jira_fields['assignee'] = proxy_through_env(jira_config.get("assignee", None))
        jira_fields['issuetype'] = proxy_through_env(jira_config.get("issue_type", 'Bug'))
        jira_fields['labels'] = proxy_through_env(jira_config.get("labels", []))
        jira_fields['watchers'] = proxy_through_env(jira_config.get("watchers", None))
        jira_fields['Epic Link'] = proxy_through_env(jira_config.get("epic_link", None))

    # tmp
    if not (jira_url and jira_user and jira_pwd and jira_project):
        logging.warning("Jira integration configuration is messed up , proceeding without Jira")
        return None

    return JiraWrapper(jira_url, jira_user, jira_pwd, jira_project, jira_fields)


def parse_email_config(config):
    emails_service, email_attachments = None, []
    emails_config = config.get('emails')

    if emails_config:
        emails_smtp_server = proxy_through_env(emails_config.get('smtp_server'))
        emails_port = proxy_through_env(emails_config.get('port'))
        emails_login = proxy_through_env(emails_config.get('login'))
        emails_password = proxy_through_env(emails_config.get('password'))
        emails_receivers_email_list = proxy_through_env(emails_config.get('receivers_email_list', '')).split(',')
        emails_subject = proxy_through_env(emails_config.get('subject'))
        emails_body = proxy_through_env(emails_config.get('body'))
        email_attachments = proxy_through_env(emails_config.get('attachments', []))

        if email_attachments:
            email_attachments = email_attachments.split(',')

        constants.JIRA_OPENED_STATUSES.extend(proxy_through_env(
            emails_config.get('open_states', '')).split(','))

        if not (emails_smtp_server and emails_login and emails_password and emails_receivers_email_list):
            logging.warning("Emails integration configuration is messed up , proceeding without Emails")
        else:
            emails_service = EmailWrapper(emails_smtp_server, emails_login, emails_password, emails_port,
                                          emails_receivers_email_list, emails_subject, emails_body)

    return emails_service, email_attachments


def parse_rp_config(config, test_name):
    reportportal_config = config.get('reportportal')
    if not reportportal_config:
        return None

    rp_config = {
        "rp_project": reportportal_config.get("rp_project_name", "Dusty"),
        "rp_launch_name": reportportal_config.get("rp_launch_name", test_name),
        "rp_url": reportportal_config.get("rp_host"),
        "rp_token": reportportal_config.get("rp_token"),
    }

    absent_params = [k for k, v in rp_config.items() if not v]

    if absent_params:
        logging.warning(f"The following ReportPortal configuration values are missing: {str(absent_params)[1:-1]}."
                        f"Proceeding without report portal integration")
        return None
    rp_config["rp_launch_tags"] = reportportal_config.get("rp_launch_tags", None)
    return rp_config


def read_config(args):
    def default_ctor(loader, tag_suffix, node):
        return tag_suffix + node.value

    config_data = args.config_data
    if not config_data:
        with open(args.config, "rb") as f:
            config_data = f.read()

    yaml.add_multi_constructor('', default_ctor)
    config = variable_substitution(yaml.load(config_data))

    return config


def config_from_yaml(args):
    config = read_config(args)

    test_name = args.suite
    if test_name not in list(config.keys()):
        raise NameError(f"Specified suite '{args.suite}' wasn't found among available suites in the config file. "
                        f"List of available suites: {list(config.keys())}")

    execution_config = config[test_name]
    generate_html = execution_config.get("html_report", False)
    generate_junit = execution_config.get("junit_report", False)
    code_path = proxy_through_env(execution_config.get("code_path", constants.PATH_TO_CODE))
    code_source = proxy_through_env(execution_config.get("code_source", constants.PATH_TO_CODE))

    if generate_html:
        logging.info("We are going to generate HTML Report")

    if generate_junit:
        logging.info("We are going to generate jUnit Report")

    # TODO: Do we really need it?
    for each in constants.READ_THROUGH_ENV:
        if each in execution_config:
            execution_config[each] = proxy_through_env(execution_config[each])

    rp_config = parse_rp_config(execution_config, test_name)
    jira_service = parse_jira_config(execution_config)
    min_priority = proxy_through_env(execution_config.get("min_priority", constants.MIN_PRIORITY))
    ptai_report_name = proxy_through_env(execution_config.get('ptai', {}).get('report_name', None))
    email_service, email_attachments = parse_email_config(execution_config)

    default_config = dict(host=execution_config.get('target_host', None),
                          port=execution_config.get('target_port', None),
                          protocol=execution_config.get('protocol', None),
                          project_name=execution_config.get('project_name', 'None'),
                          environment=execution_config.get('environment', 'None'),
                          test_type=execution_config.get('test_type', 'None'),
                          jira_service=jira_service,
                          jira_mapping=execution_config.get('jira_mapping', prepare_jira_mapping(jira_service)),
                          min_priority=min_priority,
                          rp_config=rp_config,
                          influx=execution_config.get("influx", None),
                          loki=execution_config.get("loki", None),
                          generate_html=generate_html,
                          generate_junit=generate_junit,
                          ptai_report_name=ptai_report_name,
                          code_path=code_path,
                          code_source=code_source,
                          path_to_false_positive=args.fp_config,
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

        language = execution_config.get('language')
        if language:
            config['language'] = language
            config['scan_opts'] = execution_config.get('scan_opts', '')

        tests_config[each] = config
    return default_config, tests_config


def process_results(default_config, start_time, global_results=None,
                    html_report_file=None, xml_report_file=None,
                    other_results=None, global_errors=None):
    created_jira_tickets = []
    attachments = []
    rp_client = launch_reportportal_service(default_config['rp_config'])
    if rp_client:
        rp_client.finish_test()
    default_config['execution_time'] = int(time() - start_time)
    if other_results is None:
        other_results = []
    if default_config.get('generate_html', None):
        html_report_file = HTMLReport(sorted(global_results, key=lambda item: item.severity),
                                      default_config,
                                      other_findings=sorted(other_results, key=lambda item: item.severity)).report_name
    if default_config.get('generate_junit', None):
        xml_report_file = XUnitReport(global_results, default_config).report_name
    if os.environ.get("redis_connection"):
        RedisFile(os.environ.get("redis_connection"), html_report_file, xml_report_file)
    if default_config.get('jira_service', None):
        created_jira_tickets = default_config['jira_service'].get_created_tickets()
    if default_config.get('influx', None):
        try:
            InfluxReport(global_results, other_results, created_jira_tickets, default_config)
        except BaseException as e:
            logging.error("Exception during influx reporting")
            global_errors["Influx"] = str(e)
            logging.debug(format_exc())
    if default_config.get('email_service', None):
        if html_report_file:
            attachments.append(html_report_file)
        for item in default_config.get('email_attachments', None):
            attachments.append('/attachments/' + item.strip())
        # TODO: Rework sending of emails to be not tiedly coupled with Jira
        send_emails(default_config['email_service'], True, jira_tickets_info=created_jira_tickets,
                    attachments=attachments, errors=global_errors)


def list_of_available_suites(args):
    config = read_config(args)
    suites = list(config.keys())
    return suites


def main():
    args = parse_args()
    logging_level = logging.DEBUG if args.debug or os.environ.get("debug", False) else logging.INFO

    logging.basicConfig(
        level=logging_level,
        datefmt='%Y.%m.%d %H:%M:%S',
        format='%(asctime)s - %(levelname)8s - %(message)s',
    )
    logging.raiseExceptions = False

    # Disable requests/urllib3 logging
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    # Disable qualysapi requests logging
    logging.getLogger("qualysapi.connector").setLevel(logging.WARNING)
    logging.getLogger("qualysapi.config").setLevel(logging.WARNING)
    logging.getLogger("qualysapi.util").setLevel(logging.WARNING)

    start_time = time()

    global_results = []
    global_other_results = []
    global_errors = dict()

    default_config, test_configs = config_from_yaml(args)

    # Enable Loki logging
    enable_loki_logging(default_config)

    for key in test_configs:
        results = []
        other_results = []
        config = test_configs[key]
        if key in constants.SASTY_SCANNERS_CONFIG_KEYS:
            if key == "scan_opts":
                continue
            attr_name = config[key] if 'language' in key else key
            try:
                results = getattr(SastyWrapper, attr_name)(config)
                if isinstance(results, tuple):
                    results, other_results = results
            except BaseException as e:
                logging.error("Exception during %s Scanning" % attr_name)
                global_errors[attr_name] = str(e)
                logging.debug(format_exc())
        else:
            try:
                tool_name, result = getattr(DustyWrapper, key)(config)
                results, other_results = common_post_processing(config, result, tool_name, need_other_results=True,
                                                                global_errors=global_errors)
            except BaseException as e:
                logging.error("Exception during %s Scanning" % key)
                global_errors[key] = str(e)
                logging.debug(format_exc())

        if default_config.get('jira_service', None) and config.get('jira_service', None) \
                and config.get('jira_service').valid:
            default_config['jira_service'].created_jira_tickets.extend(config.get('jira_service').get_created_tickets())

        if default_config.get('generate_html', None) or default_config.get('generate_junit', None):
            global_results.extend(results)
            global_other_results.extend(other_results)

    process_results(default_config, start_time, global_results, other_results=global_other_results,
                    global_errors=global_errors)
    flush_logs()


if __name__ == "__main__":
    main()
