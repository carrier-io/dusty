#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,R0903,R0914

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
    Influx presenter
"""

import datetime
from time import time

from dusty.constants import SEVERITIES


class InfluxPresenter:
    """ Influx presenter """

    def __init__(self, context, config):
        self.context = context
        self.config = config

    @property
    def points(self):
        """ Returns points to write """
        result = list()
        # Stats
        execution_time = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        project_name = self.context.get_meta("project_name", "None")
        build_id = f"{execution_time} - {project_name}"
        test_type = self.context.get_meta("testing_type", "None")
        jira_mapping = self.context.performers["reporting"].get_module_meta(
            "jira", "mapping", dict()
        )
        results_by_severity = dict()
        for item in self.context.findings:
            if item.get_meta("false_positive_finding", False) or \
                    item.get_meta("excluded_finding", False):
                continue
            priority = item.get_meta("severity", SEVERITIES[-1])
            if priority in jira_mapping:
                priority = jira_mapping[priority]
            if priority not in results_by_severity:
                results_by_severity[priority] = 0
            results_by_severity[priority] += 1
        results_by_severity["new_in_jira"] = \
            len(self.context.performers["reporting"].get_module_meta(
                "jira", "new_tickets", list()
            ))
        results_by_severity["total_in_jira"] = \
            results_by_severity["new_in_jira"] + \
            len(self.context.performers["reporting"].get_module_meta(
                "jira", "existing_tickets", list()
            ))
        results_by_severity["test_to_count"] = 1
        result.append({
            "measurement": "stats",
            "time": execution_time,
            "tags": {
                "build_id": build_id,
                "test_name": test_type,
                "type": test_type,
                "project": project_name
            },
            "fields": results_by_severity
        })
        # Errors
        policy = self.config.get("policy", {"Blocker": 1, "Critical": 5, "Major": 15})
        jira_tickets = list()
        jira_tickets.extend(self.context.performers["reporting"].get_module_meta(
            "jira", "new_tickets", list()
        ))
        jira_tickets.extend(self.context.performers["reporting"].get_module_meta(
            "jira", "existing_tickets", list()
        ))
        for issue in jira_tickets:
            ts = int(datetime.datetime.strptime(  # pylint: disable=C0103
                issue["created"], "%Y-%m-%dT%H:%M:%S.%f%z"
            ).timestamp())
            break_policy = "Y" if str(issue["priority"]) in policy and \
                ts + (policy[str(issue["priority"])] * 24 * 3600) < int(time()) else "N"
            issue = {
                "measurement": "errors",
                "time": execution_time,
                "tags": {
                    "build_id": build_id,
                    "description": str(issue["description"]),
                    "test_name": test_type,
                    "type": test_type,
                    "project": project_name,
                    "priority": issue["priority"],
                    "created": datetime.datetime.strptime(
                        issue["created"], "%Y-%m-%dT%H:%M:%S.%f%z"
                    ).strftime("%d %b %Y %H:%M:%S.%f"),
                    "link": str(issue["jira_url"])
                },
                "fields": {
                    "breaking_policy": break_policy,
                    "status": str(issue["status"]),
                    "assignee": str(issue["assignee"]),
                    "quantity": 1
                }
            }
            result.append(issue)
        # NB: not implemented in 1.0:
        #     - sort_results_by_issue_type (implement with canonical issue naming)
        #     - out_of_compliance_issues (implement with compliance policy)
        # Return points for InfluxDB
        return result
