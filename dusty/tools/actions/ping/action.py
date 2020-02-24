#!/usr/bin/python3
# coding=utf-8

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
    Test action
"""

from dusty.models.action import ActionModel
from dusty.tools import log


class Action(ActionModel):
    """ Test action """

    def __init__(self, context, config):
        """ Initialize action instance """
        super().__init__()
        self.context = context
        self.validate_config(config)
        self.config = config

    def run(self):
        """ Run action """
        log.info("Ping response: %s", self.config.get("response", "pong"))

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj), "response", "pong",
            comment="(optional) Response to send to log"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = []
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def get_name():
        """ Module name """
        return "ping"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "Test action"
