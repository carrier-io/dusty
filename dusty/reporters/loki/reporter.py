#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,R0902,E0401

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
    Reporter: loki logging support
"""

import logging
from queue import Queue

import pkg_resources
import requests
import logging_loki

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.reporter import ReporterModel


class Reporter(DependentModuleModel, ReporterModel):
    """ Log to Grafana Loki instance """

    def __init__(self, context):
        """ Initialize reporter instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["reporters"][__name__.split(".")[-2]]
        self._disable_loki_ssl_verification()
        self._enable_loki_logging()

    def _disable_loki_ssl_verification(self):
        # Patched function (property)
        @property
        def __session(self) -> requests.Session:
            if self._session is None:
                self._session = requests.Session()
                self._session.verify = False
                self._session.auth = self.auth or None
            return self._session
        # Replace implementation in logging_loki
        logging_loki.handlers.LokiHandler.session = __session

    def _enable_loki_logging(self):
        loki_username = self.config.get("username", None)
        loki_password = self.config.get("password", None)
        auth = None
        if loki_username and loki_password:
            auth = (loki_username, loki_password)
        if self.config.get("async", False):
            mode = "async"
            handler = logging_loki.LokiQueueHandler(
                Queue(-1),
                url=self.config.get("url"),
                tags={"project": self.context.get_meta("project_name", "Unnamed Project")},
                auth=auth,
            )
        else:
            mode = "sync"
            handler = logging_loki.LokiHandler(
                url=self.config.get("url"),
                tags={"project": self.context.get_meta("project_name", "Unnamed Project")},
                auth=auth,
            )
        logging.getLogger("").addHandler(handler)
        log.info(
            "Enabled Loki logging in %s mode for Dusty {}".format(
                pkg_resources.require("dusty")[0].version
            ),
            mode
        )

    def flush(self):
        """ Flush """
        for handler in logging.getLogger("").handlers:
            handler.flush()

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj), "url", "http://loki.example.com:3100/api/prom/push",
            comment="Loki instance URL"
        )
        data_obj.insert(
            len(data_obj), "username", "some_user",
            comment="(optional) Loki username"
        )
        data_obj.insert(
            len(data_obj), "password", "some_password",
            comment="(optional) Loki password"
        )
        data_obj.insert(
            len(data_obj), "async", True,
            comment="(optional) Use async logging"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["url"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def run_after():
        """ Return optional depencies """
        return ["email"]

    @staticmethod
    def get_name():
        """ Reporter name """
        return "Loki"

    @staticmethod
    def get_description():
        """ Reporter description """
        return "Grafana Loki reporter"
