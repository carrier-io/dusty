#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,R0903,R0913

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
    EMail item models
"""


class EMailJiraTicket:
    """ EMail Jira ticket item """

    def __init__(self, jira_id, jira_url, priority, status, open_date, description, assignee):
        self.jira_id = jira_id
        self.jira_url = jira_url
        self.priority = priority
        self.status = status
        self.open_date = open_date
        self.description = description
        self.assignee = assignee


class EMailError:
    """ EMail error item """

    def __init__(self, tool, title):
        self.tool = tool
        self.title = title
