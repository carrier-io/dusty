#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,E0401,W0702,W0703

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
    Scanner: dependencycheck
"""

import os
import shlex
import shutil
import tempfile
import subprocess

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.scanner import ScannerModel

from .parser import parse_findings


class Scanner(DependentModuleModel, ScannerModel):
    """ Scanner class """

    def __init__(self, context):
        """ Initialize scanner instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["scanners"][__name__.split(".")[-3]][__name__.split(".")[-2]]

    def execute(self):
        """ Run the scanner """
        # Prepare parameters
        additional_parameters = shlex.split(self.config.get("comp_opts", ""))
        # Make temporary directory
        output_dir = tempfile.mkdtemp()
        log.debug("Output directory: %s", output_dir)
        # Run task
        tool_options = list()
        #
        db_path = self.config.get("db_path", None)
        if db_path is not None:
            log.info("Setting local DB directory: %s", db_path)
            tool_options.append("-d")
            tool_options.append(db_path)
        #
        if self.config.get("skip_update", True):
            tool_options.append("-n")
        #
        target_path = None
        if self.config.get("code", None) is not None:
            target_path = self.config.get("code")
        else:
            target_path = self.config.get("comp_path")
        #
        task = subprocess.run(["dependency-check.sh"] + tool_options + [
            "-f", "JSON",
            "-o", output_dir, "-s", target_path
        ] + additional_parameters, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log.log_subprocess_result(task)
        output_file = os.path.join(output_dir, "dependency-check-report.json")
        parse_findings(output_file, self)
        # Save intermediates
        self.save_intermediates(output_file, task)

    def save_intermediates(self, output_file, task):
        """ Save scanner intermediates """
        if self.config.get("save_intermediates_to", None):
            log.info("Saving intermediates")
            base = os.path.join(self.config.get("save_intermediates_to"), __name__.split(".")[-2])
            try:
                # Make directory for artifacts
                os.makedirs(base, mode=0o755, exist_ok=True)
                # Save report
                shutil.copyfile(
                    output_file,
                    os.path.join(base, "report.json")
                )
                # Save output
                with open(os.path.join(base, "output.stdout"), "w") as output:
                    output.write(task.stdout.decode("utf-8", errors="ignore"))
                with open(os.path.join(base, "output.stderr"), "w") as output:
                    output.write(task.stderr.decode("utf-8", errors="ignore"))
            except:
                log.exception("Failed to save intermediates")

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(len(data_obj), "comp_path", "/path/to/code", comment="scan target")
        data_obj.insert(
            len(data_obj),
            "comp_opts", "", comment="(optional) additional options"
        )
        data_obj.insert(
            len(data_obj), "save_intermediates_to", "/data/intermediates/dast",
            comment="(optional) Save scan intermediates (raw results, logs, ...)"
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
        return "dependencycheck"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "Dependency-Check software composition analysis"
