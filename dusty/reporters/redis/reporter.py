#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,E0401

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
    Reporter: redis
"""

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.reporter import ReporterModel

from .legacy import RedisFile


class Reporter(DependentModuleModel, ReporterModel):
    """ Report findings from scanners """

    def __init__(self, context):
        """ Initialize reporter instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["reporters"][__name__.split(".")[-2]]

    def report(self):
        """ Report """
        # Prepare wrapper
        log.info("Saving HTML/XML reports (if any) to redis using legacy wrapper")
        RedisFile(
            self.config.get("connection_string"),
            self.context.performers["reporting"].get_module_meta("html", "report_file", None),
            self.context.performers["reporting"].get_module_meta("junit", "report_file", None)
        )

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj),
            "connection_string", "redis://redis.example.com:6379/0",
            comment="Redis connection string"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["connection_string"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def run_after():
        """ Return optional depencies """
        return ["html", "junit"]

    @staticmethod
    def get_name():
        """ Reporter name """
        return "Redis"

    @staticmethod
    def get_description():
        """ Reporter description """
        return "Redis reporter"
