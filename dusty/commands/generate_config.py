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
    Command: generate-config
"""

import sys
import ruamel.yaml

from ruamel.yaml.comments import CommentedMap

from dusty.tools import log, actions
from dusty.models.module import ModuleModel
from dusty.models.command import CommandModel
from dusty.models.config import ConfigModel
from dusty.scanners.performer import ScanningPerformer
from dusty.processors.performer import ProcessingPerformer
from dusty.reporters.performer import ReportingPerformer


class Command(ModuleModel, CommandModel):
    """ Generate sample config """

    def __init__(self, argparser):
        """ Initialize command instance, add arguments """
        super().__init__()
        argparser.add_argument(
            "-o", "--output", dest="output_file",
            help="path to output file (use '-' for stdout)",
            type=str, default="-"
        )

    def execute(self, args):
        """ Run the command """
        log.debug("Starting")
        # Make instances
        config = ConfigModel
        scanning = ScanningPerformer
        processing = ProcessingPerformer
        reporting = ReportingPerformer
        # Make config
        data = CommentedMap()
        # Fill config
        config.fill_config(data)
        data_obj = data["suites"]
        data_obj.insert(len(data_obj), "example", CommentedMap(), comment="Example test suite")
        data_obj["example"].insert(0, "settings", CommentedMap(), comment="Settings")
        self._fill_settings(data_obj["example"]["settings"])
        data_obj["example"].insert(
            len(data_obj["example"]), "actions", CommentedMap(), comment="Actions"
        )
        actions.fill_config(data_obj["example"]["actions"])
        scanning.fill_config(data_obj["example"])
        processing.fill_config(data_obj["example"])
        reporting.fill_config(data_obj["example"])
        # Save to file
        yaml = ruamel.yaml.YAML()
        if args.output_file == "-":
            yaml.dump(data, sys.stdout)
            return
        with open(args.output_file, "wb") as output:
            yaml.dump(data, output)
            log.info("Made sample config: %s", args.output_file)

    @staticmethod
    def _fill_settings(data_obj):
        data_obj.insert(len(data_obj), "project_name", "CARRIER-TEST", comment="Project name")
        data_obj.insert(
            len(data_obj),
            "project_description", "Carrier Test Application",
            comment="Project description (or application name)"
        )
        data_obj.insert(
            len(data_obj),
            "environment_name", "staging",
            comment="Environment under testing (branch/module for SAST)"
        )
        data_obj.insert(len(data_obj), "testing_type", "DAST", comment="DAST or SAST")
        data_obj.insert(
            len(data_obj),
            "scan_type", "full",
            comment="full, incremental or other scan description (e.g.: qualys, authorized, etc)"
        )
        data_obj.insert(
            len(data_obj), "build_id", "1", comment="Build number (or some other identifier)"
        )
        data_obj.insert(
            len(data_obj), "load_settings_from", "MY-PROJECT_Application.yaml",
            comment="(optional) Config file (object) name in upstream settings (object) provider"
        )
        data_obj.insert(
            len(data_obj),
            "dast", CommentedMap(),
            comment="Settings common to all DAST scanners"
        )
        data_obj["dast"].insert(
            0, "max_concurrent_scanners", 1,
            comment="Maximum number of concurrent DAST scanners"
        )
        data_obj.insert(
            len(data_obj),
            "sast", CommentedMap(),
            comment="Settings common to all SAST scanners"
        )
        data_obj["sast"].insert(
            0, "max_concurrent_scanners", 4,
            comment="Maximum number of concurrent SAST scanners"
        )
        data_obj.insert(
            len(data_obj),
            "processing", CommentedMap(),
            comment="Settings common to all processors"
        )
        data_obj.insert(
            len(data_obj),
            "reporters", CommentedMap(),
            comment="Settings common to all reporters"
        )

    @staticmethod
    def get_name():
        """ Command name """
        return "generate-config"

    @staticmethod
    def get_description():
        """ Command help message (description) """
        return "generate sample config"
