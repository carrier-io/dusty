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
    Scanner: trivy
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
        # Make temporary file
        output_file_fd, output_file = tempfile.mkstemp(".json")
        log.debug("Output file: %s", output_file)
        os.close(output_file_fd)
        # Run task
        set_options = list()
        tool_options = list()
        if not self.config.get("show_without_fix", False):
            set_options.append("--ignore-unfixed")
        if self.config.get("skip_update", True):
            set_options.append("--skip-update")
        #
        db_path = self.config.get("db_path", None)
        if db_path is not None:
            log.info("Setting local DB/cache directory: %s", db_path)
            tool_options.append("--cache-dir")
            tool_options.append(db_path)
        #
        task = subprocess.run([
            "trivy",
        ] + tool_options + [
            "image", "--format", "json",
        ] + set_options + [
        ] + shlex.split(self.config.get("trivy_options", "--no-progress")) + [
            "--timeout", self.config.get("timeout", "1h"),
            "--output", output_file, self.config.get("code"),
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log.log_subprocess_result(task)
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
        data_obj.insert(len(data_obj), "code", "image:tag", comment="scan target")
        data_obj.insert(
            len(data_obj), "timeout", "1h",
            comment="(optional) Scan timeout. Default: 1h"
        )
        data_obj.insert(
            len(data_obj), "skip_update", True,
            comment="(optional) Do not update on start (for CI/CD usage)"
        )
        data_obj.insert(
            len(data_obj), "show_without_fix", False,
            comment="(optional) Display findings without fix"
        )
        data_obj.insert(
            len(data_obj), "show_with_temp_id", False,
            comment="(optional) Display findings with TEMP-* ID"
        )
        data_obj.insert(
            len(data_obj), "show_without_description", True,
            comment="(optional) Display findings without description"
        )
        data_obj.insert(
            len(data_obj), "trivy_options", "--no-progress",
            comment="(optional) Additional options for Trivy"
        )
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
        return "trivy"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "Trivy: A Simple and Comprehensive Vulnerability Scanner for Containers"
