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
    Processor: min_severity_filter
"""

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.processor import ProcessorModel
from dusty.constants import SEVERITIES

from . import constants


class Processor(DependentModuleModel, ProcessorModel):
    """ Process findings: filter low-level items """

    def __init__(self, context):
        """ Initialize processor instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["processing"][__name__.split(".")[-2]]

    def execute(self):
        """ Run the processor """
        severity = self.config.get("severity", constants.DEFAULT_SEVERITY)
        log.info("Filtering findings below %s level", severity)
        for item in self.context.findings:
            if SEVERITIES.index(item.get_meta("severity", SEVERITIES[-1])) > \
                    SEVERITIES.index(severity):
                item.set_meta("information_finding", True)

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj), "severity", "High",
            comment="Minimal severity level to report, one of: Critical, High, Medium, Low, Info"
        )

    @staticmethod
    def get_name():
        """ Module name """
        return "Minimal severity filter"

    @staticmethod
    def get_description():
        """ Module description """
        return "Filters findings below minimal severity level"
