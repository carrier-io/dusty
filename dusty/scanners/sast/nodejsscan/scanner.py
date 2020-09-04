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
    Scanner: nodejsscan
"""

import os
import json
import builtins

try:
    import core.scanner as njsscan  # pylint: disable=E0611
except:
    njsscan = None  # pylint: disable=C0103

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
        # Check if we are running inside SAST container
        if njsscan is None:
            log.error("NodeJsScan is not installed in this environment")
            return
        # Replace print function to hide njsscan print()s
        original_print = print
        builtins.print = lambda *args, **kwargs: log.debug(" ".join([str(item) for item in args]))
        try:
            # Prepare excludes
            excludes = self.config.get("excludes", list())
            if not isinstance(excludes, list):
                excludes = [item.strip() for item in excludes.split(",")]
            log.debug("Excludes: %s", excludes)
            # Collect files to scan
            scan_target = list()
            base = os.path.normpath(self.config.get("code"))
            for root, _, files in os.walk(base):
                # Normalize relative dir path
                subpath = os.path.normpath(root)[len(base):]
                if subpath.startswith(os.sep):
                    subpath = subpath[len(os.sep):]
                # Check if dir (or any parent) is in excludes
                skip_dir = False
                for item in excludes:
                    if item.endswith(os.sep) and subpath.startswith(item):
                        skip_dir = True
                # Skip dir if needed
                if subpath + os.sep in excludes or skip_dir:
                    log.debug("Skipping dir %s", root)
                    continue
                # Iterate files
                for name in files:
                    target = os.path.join(root, name)
                    # Skip file if in excludes (direct match)
                    if os.path.join(subpath, name) in excludes:
                        log.debug("Skipping file %s", target)
                        continue
                    # Add to files to scan
                    scan_target.append(target)
            # Run scanner
            result = njsscan.scan_file(scan_target)
        finally:
            # Restore print function
            builtins.print = original_print
        # Parse result
        parse_findings(result, self)
        # Save intermediates
        self.save_intermediates(result)

    def save_intermediates(self, result):
        """ Save scanner intermediates """
        if self.config.get("save_intermediates_to", None):
            log.info("Saving intermediates")
            base = os.path.join(self.config.get("save_intermediates_to"), __name__.split(".")[-2])
            try:
                # Make directory for artifacts
                os.makedirs(base, mode=0o755, exist_ok=True)
                # Save report
                with open(os.path.join(base, "report.json"), "w") as output:
                    json.dump(result, output)
            except:
                log.exception("Failed to save intermediates")

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(len(data_obj), "code", "/path/to/code", comment="scan target")
        data_obj.insert(
            len(data_obj),
            "excludes", "path/to/dir/, path/to/file",
            comment="(optional) Excludes. Also supports YAML list syntax"
        )
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
        return "nodejsscan"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "NodeJsScan static security code scanner"
