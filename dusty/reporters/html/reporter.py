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
    Reporter: html
"""

from jinja2 import Environment, PackageLoader, select_autoescape

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.reporter import ReporterModel

from . import constants
from .presenter import HTMLPresenter


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
        file = self.config.get("file", constants.DEFAULT_REPORT_FILE)
        if self.config.get("format_file_name", True):
            file = file.format(**self.context.meta)
        log.info("Creating HTML report %s", file)
        environment = Environment(
            loader=PackageLoader(
                "dusty",
                f"{'/'.join(__name__.split('.')[1:-1])}/data"
            ),
            autoescape=select_autoescape(["html", "xml"])
        )
        template = environment.get_template("report.html")
        data = template.render(presenter=HTMLPresenter(self.context, self.config))
        with open(file, "w") as report:
            report.write(data)
        self.set_meta("report_file", file)

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(len(data_obj), "file", "/path/to/report.html", comment="HTML report path")
        data_obj.insert(
            len(data_obj), "format_file_name", True,
            comment="(optional) Allow to use {variables} inside file path"
        )
        data_obj.insert(
            len(data_obj), "group_by_endpoint", False,
            comment="(optional) Create finding groups for every endpoint"
        )

    @staticmethod
    def get_name():
        """ Reporter name """
        return "HTML"

    @staticmethod
    def get_description():
        """ Reporter description """
        return "HTML reporter"
