#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,E0401,W0702,W0703

#   Copyright 2020 getcarrier.io
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
    Scanner: csharp
"""

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.scanner import ScannerModel


class Scanner(DependentModuleModel, ScannerModel):
    """ Scanner class """

    def __init__(self, context):
        """ Initialize scanner instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["scanners"][__name__.split(".")[-3]][__name__.split(".")[-2]]
        self.set_meta("meta_scanner", True)

    def prepare(self):
        """ Prepare scanner """
        scanners = ["insider"]
        scanner_configs = {
            "insider": {
                "tech": "csharp",
            }
        }
        for scanner in scanners:
            log.info("Adding %s scanner", scanner)
            if scanner in scanner_configs:
                scanner_config = scanner_configs[scanner].copy()
                scanner_config.update(self.config)
            else:
                scanner_config = self.config
            self.context.performers["scanning"].schedule_scanner("sast", scanner, scanner_config)

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(len(data_obj), "code", "/path/to/code", comment="scan target")
        data_obj.insert(
            len(data_obj), "save_intermediates_to", "/data/intermediates/dast",
            comment="(optional) Save scan intermediates (raw results, logs, ...)"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["code"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def get_name():
        """ Module name """
        return "csharp"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "SAST scanner"
