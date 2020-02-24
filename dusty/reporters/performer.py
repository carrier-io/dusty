#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,R0903,W0702,W0703

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
    Reporting performer
"""

import importlib
import traceback
import pkgutil

from ruamel.yaml.comments import CommentedMap  # pylint: disable=E0401

from dusty.tools import log
from dusty.tools import dependency
from dusty.models.module import ModuleModel
from dusty.models.performer import PerformerModel
from dusty.models.reporter import ReporterModel
from dusty.models.error import Error

from . import constants


class ReportingPerformer(ModuleModel, PerformerModel, ReporterModel):
    """ Perform reporting """

    def __init__(self, context):
        """ Initialize instance """
        super().__init__()
        self.context = context

    def prepare(self):
        """ Prepare for action """
        log.debug("Preparing")
        config = self.context.config["reporters"]
        config_items = [
            item for item in list(config) if not isinstance(config[item], bool) or config[item]
        ]
        disabled_items = [
            item for item in list(config) if isinstance(config[item], bool) and not config[item]
        ]
        # Schedule reporters
        try:
            all_reporters = dependency.resolve_name_order(
                config_items + [
                    item for item in constants.DEFAULT_REPORTERS if item not in disabled_items
                ], "dusty.reporters.{}.reporter", "Reporter"
            )
        except:
            all_reporters = [
                item for item in constants.DEFAULT_REPORTERS if item not in disabled_items
            ] + config_items
        for reporter_name in all_reporters:
            try:
                self.schedule_reporter(reporter_name, dict())
            except:
                log.exception("Failed to prepare reporter %s", reporter_name)
                error = Error(
                    tool=reporter_name,
                    error=f"Failed to prepare reporter {reporter_name}",
                    details=f"```\n{traceback.format_exc()}\n```"
                )
                self.context.errors.append(error)
        # Resolve depencies once again
        dependency.resolve_depencies(self.context.reporters)

    def perform(self):
        """ Perform action """
        self.report()

    def get_module_meta(self, module, name, default=None):
        """ Get submodule meta value """
        try:
            module_name = importlib.import_module(
                f"dusty.reporters.{module}.reporter"
            ).Reporter.get_name()
            if module_name in self.context.reporters:
                return self.context.reporters[module_name].get_meta(name, default)
            return default
        except:
            return default

    def set_module_meta(self, module, name, value):
        """ Set submodule meta value """
        try:
            module_name = importlib.import_module(
                f"dusty.reporters.{module}.reporter"
            ).Reporter.get_name()
            if module_name in self.context.reporters:
                self.context.reporters[module_name].set_meta(name, value)
        except:
            pass

    def schedule_reporter(self, reporter_name, reporter_config):
        """ Schedule reporter run in current context after all already configured reporters """
        try:
            # Init reporter instance
            reporter = importlib.import_module(
                f"dusty.reporters.{reporter_name}.reporter"
            ).Reporter
            if reporter.get_name() in self.context.reporters:
                log.debug("Reporter %s already scheduled", reporter_name)
                return
            # Prepare config
            config = self.context.config["reporters"]
            if reporter_name not in config or not isinstance(config[reporter_name], dict):
                config[reporter_name] = dict()
            if "reporters" in self.context.config["settings"]:
                general_config = self.context.config["settings"]["reporters"]
                merged_config = general_config.copy()
                merged_config.update(config[reporter_name])
                config[reporter_name] = merged_config
            config[reporter_name].update(reporter_config)
            # Validate config
            reporter.validate_config(config[reporter_name])
            # Add to context
            self.context.reporters[reporter.get_name()] = reporter(self.context)
            # Resolve depencies
            dependency.resolve_depencies(self.context.reporters)
            # Done
            log.debug("Scheduled reporter %s", reporter_name)
        except:
            log.exception("Failed to schedule reporter %s", reporter_name)
            error = Error(
                tool=reporter_name,
                error=f"Failed to schedule reporter {reporter_name}",
                details=f"```\n{traceback.format_exc()}\n```"
            )
            self.context.errors.append(error)

    def report(self):
        """ Report """
        log.info("Starting reporting")
        # Run reporters
        performed = set()
        perform_report_iteration = True
        while perform_report_iteration:
            perform_report_iteration = False
            for reporter_module_name in list(self.context.reporters):
                if reporter_module_name in performed:
                    continue
                performed.add(reporter_module_name)
                perform_report_iteration = True
                reporter = self.context.reporters[reporter_module_name]
                try:
                    reporter.report()
                except:
                    log.exception("Reporter %s failed", reporter_module_name)
                    error = Error(
                        tool=reporter_module_name,
                        error=f"Reporter {reporter_module_name} failed",
                        details=f"```\n{traceback.format_exc()}\n```"
                    )
                    self.context.errors.append(error)
                self.context.errors.extend(reporter.get_errors())

    def on_start(self):
        """ Called when testing starts """
        # Run reporters
        for reporter_module_name in self.context.reporters:
            reporter = self.context.reporters[reporter_module_name]
            try:
                reporter.on_start()
            except:
                log.exception("Reporter %s failed", reporter_module_name)
                error = Error(
                    tool=reporter_module_name,
                    error=f"Reporter {reporter_module_name} failed",
                    details=f"```\n{traceback.format_exc()}\n```"
                )
                self.context.errors.append(error)

    def on_finish(self):
        """ Called when testing ends """
        # Run reporters
        for reporter_module_name in self.context.reporters:
            reporter = self.context.reporters[reporter_module_name]
            try:
                reporter.on_finish()
            except:
                log.exception("Reporter %s failed", reporter_module_name)
                error = Error(
                    tool=reporter_module_name,
                    error=f"Reporter {reporter_module_name} failed",
                    details=f"```\n{traceback.format_exc()}\n```"
                )
                self.context.errors.append(error)

    def on_scanner_start(self, scanner):
        """ Called when scanner starts """
        # Run reporters
        for reporter_module_name in self.context.reporters:
            reporter = self.context.reporters[reporter_module_name]
            try:
                reporter.on_scanner_start(scanner)
            except:
                log.exception("Reporter %s failed", reporter_module_name)
                error = Error(
                    tool=reporter_module_name,
                    error=f"Reporter {reporter_module_name} failed",
                    details=f"```\n{traceback.format_exc()}\n```"
                )
                self.context.errors.append(error)

    def on_scanner_finish(self, scanner):
        """ Called when scanner ends """
        # Run reporters
        for reporter_module_name in self.context.reporters:
            reporter = self.context.reporters[reporter_module_name]
            try:
                reporter.on_scanner_finish(scanner)
            except:
                log.exception("Reporter %s failed", reporter_module_name)
                error = Error(
                    tool=reporter_module_name,
                    error=f"Reporter {reporter_module_name} failed",
                    details=f"```\n{traceback.format_exc()}\n```"
                )
                self.context.errors.append(error)

    def flush(self):
        """ Flush """
        # Run reporters
        for reporter_module_name in self.context.reporters:
            reporter = self.context.reporters[reporter_module_name]
            try:
                reporter.flush()
            except:
                log.exception("Reporter %s failed", reporter_module_name)
                error = Error(
                    tool=reporter_module_name,
                    error=f"Reporter {reporter_module_name} failed",
                    details=f"```\n{traceback.format_exc()}\n```"
                )
                self.context.errors.append(error)

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        # general_obj = data_obj["settings"]["reporters"] # This can also be used
        data_obj.insert(len(data_obj), "reporters", CommentedMap(), comment="Reporters config")
        reporters_obj = data_obj["reporters"]
        reporters_module = importlib.import_module("dusty.reporters")
        for _, name, pkg in pkgutil.iter_modules(reporters_module.__path__):
            if not pkg:
                continue
            reporter = importlib.import_module(
                "dusty.reporters.{}.reporter".format(name)
            )
            reporters_obj.insert(
                len(reporters_obj), name, CommentedMap(),
                comment=reporter.Reporter.get_description()
            )
            reporter.Reporter.fill_config(reporters_obj[name])

    @staticmethod
    def validate_config(config):
        """ Validate config """
        if "reporters" not in config:
            log.warning("No reporters defined in config")
            config["reporters"] = dict()

    @staticmethod
    def get_name():
        """ Module name """
        return "reporting"

    @staticmethod
    def get_description():
        """ Module description or help message """
        raise "performs result reporting"
