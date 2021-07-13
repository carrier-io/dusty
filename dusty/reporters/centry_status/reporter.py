#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,R0902,E0401

#   Copyright 2021 getcarrier.io
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
    Reporter: Carrier 3.0 status reporting
"""

import requests

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.reporter import ReporterModel


class Reporter(DependentModuleModel, ReporterModel):
    """ Listen to status events and report to Carrier platform """

    def __init__(self, context):
        """ Initialize reporter instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["reporters"][__name__.split(".")[-2]]
        self._enable_status_reporting()

    def _enable_status_reporting(self):
        self.context.event.subscribe("status", self._status_listener)

    def _status_listener(self, event, data):
        log.debug("Got event: event=%s, data=%s", event, data)
        requests.put(f'{self.config["url"]}/api/v1/security/{self.config["project_id"]}/update_status/{self.config["test_id"]}', json={"test_status": data})

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["url", "project_id", "test_id"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def get_name():
        """ Reporter name """
        return "Status"

    @staticmethod
    def get_description():
        """ Reporter description """
        return "Scan status reporter"
