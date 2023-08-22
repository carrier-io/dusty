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
    Command: run
"""

import os
import pkg_resources

from dusty.tools import log, actions, git
from dusty import constants
from dusty.models.module import ModuleModel
from dusty.models.command import CommandModel
from dusty.models.context import RunContext
from dusty.models.config import ConfigModel
from dusty.scanners.performer import ScanningPerformer
from dusty.processors.performer import ProcessingPerformer
from dusty.reporters.performer import ReportingPerformer


class Command(ModuleModel, CommandModel):
    """ Runs tests defined in config file """

    def __init__(self, argparser):
        """ Initialize command instance, add arguments """
        super().__init__()
        argparser.add_argument(
            "-b", "--config-seed", dest="config_seed",
            help="configuration seed/blob",
            type=str, default=constants.DEFAULT_CONFIG_SEED
        )
        argparser.add_argument(
            "-e", "--config-variable", dest="config_variable",
            help="name of environment variable with config",
            type=str, default=constants.DEFAULT_CONFIG_ENV_KEY
        )
        argparser.add_argument(
            "-c", "--config-file", dest="config_file",
            help="path to config file",
            type=str, default=constants.DEFAULT_CONFIG_PATH
        )
        argparser.add_argument(
            "-s", "--suite", dest="suite",
            help="test suite to run",
            type=str
        )
        argparser.add_argument(
            "-l", "--list-suites", dest="list_suites",
            help="list available test suites",
            action="store_true"
        )

    def execute(self, args):
        """ Run the command """
        log.debug("Starting")
        if args.call_from_legacy:
            log.warning("Called from legacy entry point")
        # Apply patches
        git.apply_patches()
        # Init context
        context = RunContext(args)
        config = ConfigModel(context)
        if args.list_suites or not args.suite:
            suites = config.list_suites(args.config_seed, args.config_variable, args.config_file)
            if not args.suite:
                log.error("Suite is not defined. Use --help to get help")
            log.info("Available suites: %s", ", ".join(suites))
            return
        # Make instances
        scanning = ScanningPerformer(context)
        processing = ProcessingPerformer(context)
        reporting = ReportingPerformer(context)
        # Add to context
        context.performers["scanning"] = scanning
        context.performers["processing"] = processing
        context.performers["reporting"] = reporting
        # Init config
        config.load(args.config_seed, args.config_variable, args.config_file, args.suite)
        scanning.validate_config(context.config)
        processing.validate_config(context.config)
        reporting.validate_config(context.config)
        # Add meta to context
        self._fill_context_meta(context)
        # Load state
        context.state.load()
        # Prepare reporters first
        reporting.prepare()
        context.event.emit("status", {
            "status": "Preparing",
            "percentage": 10,
            "description": "Carrier is preparing to run the scan",
        })
        # Run actions
        actions.run(context)
        # Prepare scanning and processing
        scanning.prepare()
        processing.prepare()
        # Perform scanning
        context.event.emit("status", {
            "status": "Scanning started",
            "percentage": 20,
            "description": "Started: scan targets with security scanners",
        })
        scanning.perform()
        context.event.emit("status", {
            "status": "Scanning finished",
            "percentage": 50,
            "description": "Finished: scan targets with security scanners",
        })
        # Perform processing
        context.event.emit("status", {
            "status": "Processing started",
            "percentage": 60,
            "description": "Started: process scan results",
        })
        processing.perform()
        context.event.emit("status", {
            "status": "Processing finished",
            "percentage": 70,
            "description": "Finished: process scan results",
        })

        # Perform reporting
        context.event.emit("status", {
            "status": "Reporting started",
            "percentage": 80,
            "description": "Started: report results",
        })
        reporting.perform()
        context.event.emit("status", {
            "status": "Reporting finished",
            "percentage": 90,
            "description": "Finished: report results",
        })
        # Run post-actions
        actions.post_run(context)
        # Done
        context.state.save()

        # Show quality gate statistics if any
        for line in context.get_meta("quality_gate_stats", list()):
            log.info(line)
        #
        context.event.emit("status", {
            "status": "Done",
            "percentage": 99,
            "description": "All done: finalizing",
        })
        #
        reporting.flush()  # Flush reporters before checking quality gate - os._exit can be called
        log.debug("Done")
        # Fail quality gate if needed
        should_fail_quality_gate = context.get_meta("fail_quality_gate", None)
        log.info("Quality gate fail status: %s", should_fail_quality_gate)
        #
        if should_fail_quality_gate:
            context.event.emit("status", {
                "status": "Failed",
                "percentage": 100,
                "description": "All done",
            })
            os._exit(1)  # pylint: disable=W0212
        elif should_fail_quality_gate is False:
            context.event.emit("status", {
                "status": "Success",
                "percentage": 100,
                "description": "All done",
            })
        else:  # should_fail_quality_gate is None
            context.event.emit("status", {
                "status": "Finished",
                "percentage": 100,
                "description": "All done",
            })

    @staticmethod
    def _fill_context_meta(context):  # pylint: disable=R0912
        # Project name
        if context.config["settings"].get("project_name", None):
            context.set_meta("project_name", context.config["settings"]["project_name"])
        else:
            context.set_meta("project_name", "UnnamedProject")
        # Project description
        if context.config["settings"].get("project_description", None):
            context.set_meta(
                "project_description", context.config["settings"]["project_description"]
            )
        else:
            context.set_meta("project_description", "Undescribed Project")
        # Environment name
        if context.config["settings"].get("environment_name", None):
            context.set_meta(
                "environment_name", context.config["settings"]["environment_name"]
            )
        else:
            context.set_meta("environment_name", "default")
        # Testing type
        if context.config["settings"].get("testing_type", None):
            context.set_meta("testing_type", context.config["settings"]["testing_type"])
        else:
            dast_scanners = len(context.config["scanners"].get("dast", dict()))
            sast_scanners = len(context.config["scanners"].get("sast", dict()))
            if dast_scanners > sast_scanners and sast_scanners == 0:
                context.set_meta("testing_type", "DAST")
            elif sast_scanners > dast_scanners and dast_scanners == 0:
                context.set_meta("testing_type", "SAST")
            else:
                context.set_meta("testing_type", "DSAST")
        # Scan type
        if context.config["settings"].get("scan_type", None):
            context.set_meta("scan_type", context.config["settings"]["scan_type"])
        else:
            context.set_meta("scan_type", context.suite)
        # Build ID
        if context.config["settings"].get("build_id", None):
            context.set_meta("build_id", context.config["settings"]["build_id"])
        else:
            context.set_meta("build_id", "0")
        # Dusty version
        context.set_meta("dusty_version", pkg_resources.require("dusty")[0].version)
        # DAST target
        if context.config["settings"].get("dast", dict()).get("target", None):
            context.set_meta("dast_target", context.config["settings"]["dast"]["target"])
        # SAST code
        if context.config["settings"].get("sast", dict()).get("code", None):
            context.set_meta(
                "sast_code", context.config["settings"]["sast"]["code"]
            )

    @staticmethod
    def get_name():
        """ Command name """
        return "run"

    @staticmethod
    def get_description():
        """ Command help message (description) """
        return "run tests according to config"
