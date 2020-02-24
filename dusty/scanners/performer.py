#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,R0903,W0702,W0703,R0914,R0912,R0915

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
    Scanning performer
"""

import importlib
import traceback
import pkgutil
import time

import concurrent.futures

from ruamel.yaml.comments import CommentedMap

from dusty.tools import log
from dusty.tools import dependency
from dusty.models.module import ModuleModel
from dusty.models.performer import PerformerModel
from dusty.models.error import Error

from . import constants


class ScanningPerformer(ModuleModel, PerformerModel):
    """ Runs scanners """

    def __init__(self, context):
        """ Initialize instance """
        super().__init__()
        self.context = context

    def prepare(self):
        """ Prepare for action """
        log.debug("Preparing")
        config = self.context.config["scanners"]
        # Schedule scanners
        for scanner_type in list(config):
            for scanner_name in list(config[scanner_type]):
                if isinstance(config[scanner_type][scanner_name], bool) and \
                        not config[scanner_type][scanner_name]:
                    continue
                try:
                    self.schedule_scanner(scanner_type, scanner_name, dict())
                except:
                    log.exception(
                        "Failed to prepare %s scanner %s",
                        scanner_type, scanner_name
                    )
                    error = Error(
                        tool=f"{scanner_type}.{scanner_name}",
                        error=f"Failed to prepare {scanner_type} scanner {scanner_name}",
                        details=f"```\n{traceback.format_exc()}\n```"
                    )
                    self.context.errors.append(error)
        # Resolve depencies once again
        dependency.resolve_depencies(self.context.scanners)

    def perform(self):
        """ Perform action """
        log.info("Starting scanning")
        reporting = self.context.performers.get("reporting", None)
        # Create executors
        executor = dict()
        settings = self.context.config["settings"]
        for scanner_type in self.context.config["scanners"]:
            max_workers = settings.get(scanner_type, dict()).get("max_concurrent_scanners", 1)
            executor[scanner_type] = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
            log.info("Made %s executor with %d workers", scanner_type.upper(), max_workers)
        # Starting scanning
        if reporting:
            reporting.on_start()
        # Submit scanners
        futures = list()
        future_map = dict()
        future_dep_map = dict()
        for item in self.context.scanners:
            scanner = self.context.scanners[item]
            scanner_type = scanner.__class__.__module__.split(".")[-3]
            scanner_module = scanner.__class__.__module__.split(".")[-2]
            depencies = list()
            for dep in scanner.depends_on() + scanner.run_after():
                if dep in future_dep_map:
                    depencies.append(future_dep_map[dep])
            future = executor[scanner_type].submit(self._execute_scanner, scanner, depencies)
            future_dep_map[scanner_module] = future
            future_map[future] = item
            futures.append(future)
        # Wait for executors to start and finish
        started = set()
        finished = set()
        while True:
            # Check for started executors
            for future in futures:
                if future not in started and (future.running() or future.done()):
                    item = future_map[future]
                    scanner = self.context.scanners[item]
                    if not scanner.get_meta("meta_scanner", False):
                        log.info(f"Started {item} ({scanner.get_description()})")
                        if reporting:
                            reporting.on_scanner_start(item)
                    # Add to started set
                    started.add(future)
            # Check for finished executors
            for future in futures:
                if future not in finished and future.done():
                    item = future_map[future]
                    try:
                        future.result()
                    except:
                        log.exception("Scanner %s failed", item)
                        error = Error(
                            tool=item,
                            error=f"Scanner {item} failed",
                            details=f"```\n{traceback.format_exc()}\n```"
                        )
                        self.context.errors.append(error)
                    # Collect scanner findings and errors
                    scanner = self.context.scanners[item]
                    scanner_type = scanner.__class__.__module__.split(".")[-3]
                    for result in scanner.get_findings():
                        result.set_meta("scanner_type", scanner_type)
                        self.context.findings.append(result)
                    for error in scanner.get_errors():
                        error.set_meta("scanner_type", scanner_type)
                        self.context.errors.append(error)
                    if not scanner.get_meta("meta_scanner", False):
                        if reporting:
                            reporting.on_scanner_finish(item)
                    # Add to finished set
                    finished.add(future)
            # Exit if all executors done
            if self._all_futures_done(futures):
                break
            # Sleep for some short time
            time.sleep(constants.EXECUTOR_STATUS_CHECK_INTERVAL)
        # All scanners completed
        if reporting:
            reporting.on_finish()

    @staticmethod
    def _execute_scanner(scanner, depencies):
        if depencies:
            concurrent.futures.wait(depencies)
        scanner.execute()

    @staticmethod
    def _all_futures_done(futures):
        for item in futures:
            if not item.done():
                return False
        return True

    def get_module_meta(self, module, name, default=None):
        """ Get submodule meta value """
        try:
            module_name = importlib.import_module(
                f"dusty.scanners.{module}.scanner"
            ).Scanner.get_name()
            if module_name in self.context.scanners:
                return self.context.scanners[module_name].get_meta(name, default)
            return default
        except:
            return default

    def set_module_meta(self, module, name, value):
        """ Set submodule meta value """
        try:
            module_name = importlib.import_module(
                f"dusty.scanners.{module}.scanner"
            ).Scanner.get_name()
            if module_name in self.context.scanners:
                self.context.scanners[module_name].set_meta(name, value)
        except:
            pass

    def schedule_scanner(self, scanner_type, scanner_name, scanner_config):
        """ Schedule scanner run in current context after all already configured scanners """
        try:
            # Init scanner instance
            scanner = importlib.import_module(
                f"dusty.scanners.{scanner_type}.{scanner_name}.scanner"
            ).Scanner
            if scanner.get_name() in self.context.scanners:
                log.debug("Scanner %s.%s already scheduled", scanner_type, scanner_name)
                return
            # Prepare config
            config = self.context.config["scanners"]
            if scanner_type not in config:
                config[scanner_type] = dict()
            if scanner_name not in config[scanner_type] or \
                    not isinstance(config[scanner_type][scanner_name], dict):
                config[scanner_type][scanner_name] = dict()
            general_config = dict()
            if "settings" in self.context.config:
                general_config = self.context.config["settings"]
            if scanner_type in general_config:
                merged_config = general_config[scanner_type].copy()
                merged_config.update(config[scanner_type][scanner_name])
                config[scanner_type][scanner_name] = merged_config
            config[scanner_type][scanner_name].update(scanner_config)
            # Validate config
            scanner.validate_config(config[scanner_type][scanner_name])
            # Add to context
            scanner = scanner(self.context)
            self.context.scanners[scanner.get_name()] = scanner
            # Resolve depencies
            dependency.resolve_depencies(self.context.scanners)
            # Prepare scanner
            scanner.prepare()
            # Done
            log.debug("Scheduled scanner %s.%s", scanner_type, scanner_name)
        except:
            log.exception(
                "Failed to schedule %s scanner %s",
                scanner_type, scanner_name
            )
            error = Error(
                tool=f"{scanner_type}.{scanner_name}",
                error=f"Failed to schedule {scanner_type} scanner {scanner_name}",
                details=f"```\n{traceback.format_exc()}\n```"
            )
            self.context.errors.append(error)

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(len(data_obj), "scanners", CommentedMap(), comment="Scanners config")
        scanner_obj = data_obj["scanners"]
        scanners_module = importlib.import_module("dusty.scanners")
        for _, name, pkg in pkgutil.iter_modules(scanners_module.__path__):
            if not pkg:
                continue
            # general_scanner_obj = data_obj["settings"][name] # This can also be used
            scanner_type = importlib.import_module("dusty.scanners.{}".format(name))
            scanner_obj.insert(len(scanner_obj), name, CommentedMap())
            inner_obj = scanner_obj[name]
            for _, inner_name, inner_pkg in pkgutil.iter_modules(scanner_type.__path__):
                if not inner_pkg:
                    continue
                try:
                    scanner = importlib.import_module(
                        "dusty.scanners.{}.{}.scanner".format(name, inner_name)
                    )
                    inner_obj.insert(
                        len(inner_obj), inner_name, CommentedMap(),
                        comment=scanner.Scanner.get_description()
                    )
                    scanner.Scanner.fill_config(inner_obj[inner_name])
                except:
                    pass  # Skip scanner, it may be DAST scanner (in SAST image) or vice versa

    @staticmethod
    def validate_config(config):
        """ Validate config """
        if "scanners" not in config:
            log.warning("No scanners defined in config")
            config["scanners"] = dict()

    @staticmethod
    def get_name():
        """ Module name """
        return "scanning"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "performs scanning"
