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
import json
import random
import string
import logging
import threading
from subprocess import Popen, PIPE
from datetime import datetime
from dusty import constants as c
from traceback import format_exc


def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def report_to_rp(config, result, issue_name):
    if config.get("rp_config"):
        rp_data_writer = config['rp_data_writer']
        rp_data_writer.start_test_item(issue=issue_name, tags=[], description=f"Results of {issue_name} scan",
                                       item_type="SUITE")
        for item in result:
            item.rp_item(rp_data_writer)
        rp_data_writer.finish_test_item()


def report_to_jira(config, result):
    if config.get('jira_service') and config.get('jira_service').valid:
        config.get('jira_service').connect()
        jira_mapping = config.get('jira_mapping', None)
        logging.debug("Jira mapping: %s", str(jira_mapping))
        for item in result:
            item.jira(config['jira_service'], jira_mapping)
    elif config.get('jira_service') and not config.get('jira_service').valid:
        print("Jira Configuration incorrect, please fix ... ")


def send_emails(emails_service, jira_is_used, jira_tickets_info, attachments, errors=None):
    if emails_service and emails_service.valid:
        if jira_is_used:
            if jira_tickets_info:
                html = """\
                        <p>{}</p>
                        <table>
                            <tr>
                                <th>JIRA ID</th>
                                <th>PRIORITY</th>
                                <th>STATUS</th>
                                <th>OPEN DATE</th>
                                <th>DESCRIPTION</th>
                                <th>ASSIGNEE</th>
                            </tr>
                            {}
                        </table>
                    """
                tr = '<tr><td><a href="{}">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'
                new_issues_trs = []
                all_issues_trs = []
                for issue in jira_tickets_info:
                    issue_date = datetime.strptime(issue['open_date'],
                                                   '%Y-%m-%dT%H:%M:%S.%f%z').strftime('%d %b %Y %H:%M')
                    _tr = tr.format(issue['link'], issue['key'], issue['priority'], issue['status'],
                                    issue_date, issue['description'], issue['assignee'])
                    if issue['status'] in c.JIRA_OPENED_STATUSES:
                        all_issues_trs.append(_tr)
                    if issue['new']:
                        new_issues_trs.append(_tr)
                if new_issues_trs:
                    html_body = html.format('Here’s the list of new security issues: ',
                                            '\n'.join(new_issues_trs))
                else:
                    html_body = '<p>No new security issues bugs found.</p>'
                if all_issues_trs:
                    html_body += '\n' + html.format('<br><br>Here’s the list of existing security issues: ',
                                                    '\n'.join(all_issues_trs))
            else:
                html_body = '<p>No new security issues bugs found.</p>'
        else:
            html_body = '<p>Please see the results attached.</p>'
        if errors:
            html_body += '\n' + "<p>Warning: errors occurred, scan results may be incomplete.</p>"
            html_body += "<table>"
            html_body += "<tr><th>TOOL</th><th>ERROR</th></tr>"
            for tool in errors:
                html_body += "<tr><td>{}</td><td>{}</td></tr>".format(tool, errors[tool])
            html_body += "</table>"
        html_style = """
                    table, th, td {
                      border: 1px solid black;
                      border-collapse: collapse;
                      padding: 0px 5px;
                    }
                """
        emails_service.send(html_body=html_body, html_style=html_style, attachments=attachments)
    elif emails_service and not emails_service.valid:
        print("Email Configuration incorrect, please fix ... ")


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


def process_false_positives(results, config):
    path_to_config = config.get('path_to_false_positive', c.FALSE_POSITIVE_CONFIG)
    false_positives = []
    if os.path.exists(path_to_config):
        with open(path_to_config, 'r') as f:
            for line in f.readlines():
                if line.strip():
                    false_positives.append(line.strip())
    if not false_positives:
        return results
    to_remove = []
    results = list(results)
    for index in range(len(results)):
        if results[index].get_hash_code() in false_positives:
            to_remove.append(results[index])
    for _ in to_remove:
        results.pop(results.index(_))
    return results


def process_min_priority(config, results, other_results=None):
    to_remove = []
    results = list(results)
    for item in results:
        if c.JIRA_SEVERITIES.get(c.SEVERITY_MAPPING.get(item.finding['severity'])) > \
                c.JIRA_SEVERITIES.get(config.get('min_priority', c.MIN_PRIORITY)):
            to_remove.append(item)
    for _ in to_remove:
        item = results.pop(results.index(_))
        if isinstance(other_results, list):
            other_results.append(item)
    return results


def common_post_processing(config, result, tool_name, need_other_results=False, global_errors=None):
    other_results = []
    filtered_result = process_false_positives(result, config)
    filtered_result = process_min_priority(config, filtered_result, other_results=other_results)
    try:
        report_to_rp(config, filtered_result, tool_name)
    except BaseException as e:
        print("Failed to report issues in RP")
        if os.environ.get("debug", False):
            print(format_exc())
        if isinstance(global_errors, dict):
            global_errors["ReportPortal"] = str(e)
    try:
        report_to_jira(config, filtered_result)
    except BaseException as e:
        print("Failed to report issues in Jira")
        if os.environ.get("debug", False):
            print(format_exc())
        if isinstance(global_errors, dict):
            global_errors["Jira"] = str(e)
    if need_other_results:
        return filtered_result, other_results
    return filtered_result


def ptai_post_processing(config, result):
    filtered_result = process_false_positives(result, config)
    filtered_result = process_min_priority(config, filtered_result)
    report_to_jira(config, filtered_result)
    return filtered_result


def run_in_parallel(fns):
    threads = []
    results = []
    for fn, args in fns:
        thread = threading.Thread(target=fn, args=(args, results))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    return results


def define_jira_priority(severity, priority_mapping=None):
    priority = c.SEVERITY_MAPPING[severity]
    if priority_mapping and priority in priority_mapping:
        priority = priority_mapping[priority]
    return priority


def get_project_priorities(jira_client, project, issue_type="Bug"):
    """ Returns list of Jira priorities in project """
    try:
        meta = jira_client.createmeta(
            projectKeys=project,
            issuetypeNames=issue_type,
            expand="projects.issuetypes.fields"
        )
        logging.debug("Got metadata for %d projects", len(meta["projects"]))
        if not meta["projects"]:
            logging.error(
                "No meta returned for %s with type %s", project, issue_type
            )
            return []
        project_meta = meta["projects"][0]
        logging.debug(
            "Got metadata for %d issuetypes", len(project_meta["issuetypes"])
        )
        if not project_meta["issuetypes"]:
            logging.error("No %s in %s", issue_type, project)
            return []
        issue_types = project_meta["issuetypes"][0]
        if "priority" not in issue_types["fields"]:
            logging.error("No priority field in %s", project)
            return []
        priorities = [
            priority["name"] for priority in \
                issue_types["fields"]["priority"]["allowedValues"]
        ]
        return priorities
    except:  # pylint: disable=W0702
        logging.exception("Failed to get meta for %s", project)
        return []


def prepare_jira_mapping(jira_service):
    """ Make Jira mapping (for projects that are using custom values) """
    if not jira_service or not jira_service.valid:
        return None
    jira_service.connect()
    issue_type = "Bug"
    if jira_service.fields["issuetype"]["name"] != "!default_issuetype":
        issue_type = jira_service.fields["issuetype"]["name"]
    project_priorities = get_project_priorities(
        jira_service.client,
        jira_service.project,
        issue_type
    )
    if not project_priorities:
        jira_service.client.close()
        return None
    logging.debug(
        "%s %s priorities: %s",
        jira_service.project, issue_type, str(project_priorities)
    )
    mapping = dict()
    for severity in c.JIRA_SEVERITIES:
        if severity not in project_priorities:
            for alternative in c.JIRA_ALTERNATIVES[severity]:
                if alternative in project_priorities:
                    logging.warning(
                        "Mapping %s %s Jira priority: %s -> %s",
                        jira_service.project, issue_type,
                        severity, alternative
                    )
                    mapping[severity] = alternative
                    break
            if severity not in mapping:
                logging.error("Failed to find Jira mapping for %s", severity)
    jira_service.client.close()
    return mapping


def get_dependencies(file_path, add_devdep=False):
    package_json = json.load(open(f'{file_path}/package.json'))
    deps = list(package_json.get('dependencies', {}).keys())
    if add_devdep:
        deps.extend(list(package_json.get('devDependencies', {}).keys()))
    return deps
