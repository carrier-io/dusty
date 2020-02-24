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
    Processing performer
"""

import importlib
import traceback
import pkgutil

from ruamel.yaml.comments import CommentedMap  # pylint: disable=E0401

from dusty.tools import log
from dusty.tools import dependency
from dusty.models.module import ModuleModel
from dusty.models.performer import PerformerModel
from dusty.models.error import Error

from . import constants


class ProcessingPerformer(ModuleModel, PerformerModel):
    """ Process findings """

    def __init__(self, context):
        """ Initialize instance """
        super().__init__()
        self.context = context

    def prepare(self):
        """ Prepare for action """
        log.debug("Preparing")
        config = self.context.config.get("processing")
        config_items = [
            item for item in list(config) if not isinstance(config[item], bool) or config[item]
        ]
        disabled_items = [
            item for item in list(config) if isinstance(config[item], bool) and not config[item]
        ]
        # Schedule processors
        try:
            all_processors = dependency.resolve_name_order(
                config_items + [
                    item for item in constants.DEFAULT_PROCESSORS if item not in disabled_items
                ], "dusty.processors.{}.processor", "Processor"
            )
        except:
            all_processors = [
                item for item in constants.DEFAULT_PROCESSORS if item not in disabled_items
            ] + config_items
        for processor_name in all_processors:
            try:
                self.schedule_processor(processor_name, dict())
            except:
                log.exception("Failed to prepare processor %s", processor_name)
                error = Error(
                    tool=processor_name,
                    error=f"Failed to prepare processor {processor_name}",
                    details=f"```\n{traceback.format_exc()}\n```"
                )
                self.context.errors.append(error)
        # Resolve depencies once again
        dependency.resolve_depencies(self.context.processors)

    def perform(self):
        """ Perform action """
        log.info("Starting processing")
        # Run processors
        performed = set()
        perform_processing_iteration = True
        while perform_processing_iteration:
            perform_processing_iteration = False
            for processor_module_name in list(self.context.processors):
                if processor_module_name in performed:
                    continue
                performed.add(processor_module_name)
                perform_processing_iteration = True
                processor = self.context.processors[processor_module_name]
                try:
                    processor.execute()
                except:
                    log.exception("Processor %s failed", processor_module_name)
                    error = Error(
                        tool=processor_module_name,
                        error=f"Processor {processor_module_name} failed",
                        details=f"```\n{traceback.format_exc()}\n```"
                    )
                    self.context.errors.append(error)
                self.context.errors.extend(processor.get_errors())

    def get_module_meta(self, module, name, default=None):
        """ Get submodule meta value """
        try:
            module_name = importlib.import_module(
                f"dusty.processors.{module}.processor"
            ).Processor.get_name()
            if module_name in self.context.processors:
                return self.context.processors[module_name].get_meta(name, default)
            return default
        except:
            return default

    def set_module_meta(self, module, name, value):
        """ Set submodule meta value """
        try:
            module_name = importlib.import_module(
                f"dusty.processors.{module}.processor"
            ).Processor.get_name()
            if module_name in self.context.processors:
                self.context.processors[module_name].set_meta(name, value)
        except:
            pass

    def schedule_processor(self, processor_name, processor_config):
        """ Schedule processor run in current context after all already configured processors """
        try:
            # Init processor instance
            processor = importlib.import_module(
                f"dusty.processors.{processor_name}.processor"
            ).Processor
            if processor.get_name() in self.context.processors:
                log.debug("Processor %s already scheduled", processor_name)
                return
            # Prepare config
            config = self.context.config["processing"]
            if processor_name not in config or not isinstance(config[processor_name], dict):
                config[processor_name] = dict()
            if "processing" in self.context.config["settings"]:
                general_config = self.context.config["settings"]["processing"]
                merged_config = general_config.copy()
                merged_config.update(config[processor_name])
                config[processor_name] = merged_config
            config[processor_name].update(processor_config)
            # Validate config
            processor.validate_config(config[processor_name])
            # Add to context
            self.context.processors[processor.get_name()] = processor(self.context)
            # Resolve depencies
            dependency.resolve_depencies(self.context.processors)
            # Done
            log.debug("Scheduled processor %s", processor_name)
        except:
            log.exception("Failed to schedule processor %s", processor_name)
            error = Error(
                tool=processor_name,
                error=f"Failed to schedule processor {processor_name}",
                details=f"```\n{traceback.format_exc()}\n```"
            )
            self.context.errors.append(error)

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        # general_obj = data_obj["settings"]["processing"] # This can also be used
        data_obj.insert(len(data_obj), "processing", CommentedMap(), comment="Processing config")
        processing_obj = data_obj["processing"]
        processing_module = importlib.import_module("dusty.processors")
        for _, name, pkg in pkgutil.iter_modules(processing_module.__path__):
            if not pkg:
                continue
            processor = importlib.import_module(
                "dusty.processors.{}.processor".format(name)
            )
            processing_obj.insert(
                len(processing_obj), name, CommentedMap(),
                comment=processor.Processor.get_description()
            )
            processor.Processor.fill_config(processing_obj[name])

    @staticmethod
    def validate_config(config):
        """ Validate config """
        if "processing" not in config:
            log.warning("No processing defined in config")
            config["processing"] = dict()

    @staticmethod
    def get_name():
        """ Module name """
        return "processing"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "performs result processing"
