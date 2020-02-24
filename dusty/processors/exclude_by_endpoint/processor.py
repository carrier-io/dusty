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
    Processor: exclude_by_endpoint
"""

import re

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.processor import ProcessorModel
from dusty.models.finding import DastFinding, SastFinding


class Processor(DependentModuleModel, ProcessorModel):
    """ Process findings: exclude findings for specific endpoints """

    def __init__(self, context):
        """ Initialize processor instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["processing"][__name__.split(".")[-2]]

    def execute(self):
        """ Run the processor """
        log.info("Excluding specific findings")
        # Collect and compile regexes
        endpoint_regexes = list()
        for regex in self.config.get("endpoint_regex", list()):
            try:
                regex_item = (re.compile(regex), regex)
                endpoint_regexes.append(regex_item)
            except:  # pylint: disable=W0702
                log.exception("Failed to compile regex '%s'", regex)
        # Collect and compile "keep" regexes
        endpoint_keep_regexes = list()
        for regex in self.config.get("endpoint_keep_regex", list()):
            try:
                regex_item = (re.compile(regex), regex)
                endpoint_keep_regexes.append(regex_item)
            except:  # pylint: disable=W0702
                log.exception("Failed to compile regex '%s'", regex)
        # Process finding endpoints
        for item in self.context.findings:
            if isinstance(item, (DastFinding, SastFinding)):
                force_keep_finding = False
                for endpoint in item.get_meta("endpoints", list()):
                    for regex, regex_src in endpoint_keep_regexes:
                        if regex.match(endpoint.raw):
                            log.info(
                                "Keeping finding '%s' because of endpoint keep regex '%s'",
                                item.title, regex_src
                            )
                            force_keep_finding = True
                    if force_keep_finding:
                        continue
                    for regex, regex_src in endpoint_regexes:
                        if regex.match(endpoint.raw):
                            log.info(
                                "Excluding finding '%s' because of endpoint regex '%s'",
                                item.title, regex_src
                            )
                            item.set_meta("excluded_finding", True)

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj), "endpoint_regex", ["src/test/.*"],
            comment="Endpoint regex to exclude"
        )
        data_obj.insert(
            len(data_obj), "endpoint_keep_regex", ["src/test/production.*"],
            comment="(optional) Endpoint regex to keep (even if excluded by endpoint_regex)"
        )

    @staticmethod
    def get_name():
        """ Module name """
        return "Exclude by endpoint"

    @staticmethod
    def get_description():
        """ Module description """
        return "Excludes findings that belong to endpoints specified by regex"
