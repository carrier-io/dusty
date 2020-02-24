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
    Reporter: influx
"""

from influxdb import InfluxDBClient

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.reporter import ReporterModel

from . import constants
from .presenter import InfluxPresenter


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
        log.info("Reporting to Influx")
        presenter = InfluxPresenter(self.context, self.config)
        # Prepare points
        points = presenter.points
        log.info("Writing %d points", len(points))
        # Write to Influx
        client = InfluxDBClient(
            self.config.get("host"),
            int(self.config.get("port", constants.DEFAULT_SERVER_PORT)),
            path=self.config.get("path", ""),
            database=self.config.get("db", "prodsec"),
            username=self.config.get("login", ""),
            password=self.config.get("password", ""),
            ssl=bool(self.config.get("ssl", False)),
            verify_ssl=bool(self.config.get("verify_ssl", False))
        )
        client.write_points(points)

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(len(data_obj), "host", "influx.example.com", comment="Influx server host")
        data_obj.insert(len(data_obj), "port", "8086", comment="(optional) Influx server port")
        data_obj.insert(
            len(data_obj),
            "path", "influxdb", comment="(optional) Path to Influx (if InfluxDB is behind Traefik)"
        )
        data_obj.insert(len(data_obj), "db", "prodsec", comment="(optional) Database name")
        data_obj.insert(
            len(data_obj), "login", "some_username", comment="(optional) Influx server login"
        )
        data_obj.insert(
            len(data_obj),
            "password", "SomeSecurePassword", comment="(optional) Influx server password"
        )
        data_obj.insert(len(data_obj), "ssl", False, comment="(optional) Use SSL connection")
        data_obj.insert(
            len(data_obj),
            "verify_ssl", False, comment="(optional) Verify SSL certificate"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["host"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def run_after():
        """ Return optional depencies """
        return ["jira"]

    @staticmethod
    def get_name():
        """ Reporter name """
        return "Influx"

    @staticmethod
    def get_description():
        """ Reporter description """
        return "Influx reporter"
