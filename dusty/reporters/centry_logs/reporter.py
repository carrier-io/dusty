#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,R0902,E0401

#   Copyright 2024 getcarrier.io
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
    Reporter: CentryCore logging support
"""

import logging
import pkg_resources

from centry_logging.handlers.eventnode import EventNodeLogHandler  # pylint: disable=E0401

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.reporter import ReporterModel


class Reporter(DependentModuleModel, ReporterModel):
    """ Log to CentryCore logging hub """

    def __init__(self, context):
        """ Initialize reporter instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["reporters"][__name__.split(".")[-2]]
        self._enable_loki_logging()

    def _enable_loki_logging(self):
        handler = EventNodeLogHandler(self.config)
        handler.setFormatter(log.filter_formatters[0])
        #
        logging.getLogger("").addHandler(handler)
        logging.getLogger("arbiter.eventnode").setLevel(logging.CRITICAL)
        #
        log.info(
            "Enabled Centry logging for Dusty %s",
            pkg_resources.require("dusty")[0].version
        )

    def flush(self):
        """ Flush """
        for handler in logging.getLogger("").handlers:
            handler.flush()

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["event_node", "labels"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def run_after():
        """ Return optional depencies """
        return []

    @staticmethod
    def get_name():
        """ Reporter name """
        return "Centry Logs"

    @staticmethod
    def get_description():
        """ Reporter description """
        return "Logs reporter for Centry"
