#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,R0903,R0201,E0401,W0702,C0411

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
    Config helper
"""

import os
import re
import sys
import yaml
import pkgutil
import importlib

from ruamel.yaml.comments import CommentedMap

from dusty.models.depot import SecretDepotModel, ObjectDepotModel, StateDepotModel
from dusty.tools.module import DataModuleLoader
from dusty.tools.dict import recursive_merge, recursive_merge_existing
from dusty.tools import log, depots, seeds
from dusty import constants


class ConfigModel:
    """ Parses config """

    def __init__(self, context):
        """ Initialize context instance """
        super().__init__()
        self.context = context

    def load(self, config_seed, config_variable, config_file, suite):
        """ Load and parse config """
        config = self._load_config(config_seed, config_variable, config_file)
        if not self._validate_config_base(config, suite):
            raise ValueError("Invalid config")
        context_config = self._prepare_context_config(config, suite)
        self.context.suite = suite
        self.context.config = context_config
        log.debug("Resulting context config: %s", self.context.config)
        log.info("Loaded %s suite configuration", self.context.suite)

    def _load_config(self, config_seed, config_variable, config_file):
        log.info("Loading config from seed")
        config_data = seeds.unseed(config_seed)
        if not config_data:
            log.info("Loading config from %s", config_variable)
            config_data = os.environ.get(config_variable, None)
        if not config_data:
            log.info("Loading config from %s", config_file)
            with open(config_file, "rb") as file_:
                config_data = file_.read()
        config = self._variable_substitution(
            yaml.load(
                os.path.expandvars(config_data),
                Loader=yaml.FullLoader
            )
        )
        return config

    def _variable_substitution(self, obj):
        """ Allows to use raw environmental variables inside YAML/JSON config """
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                obj[self._variable_substitution(key)] = \
                    self._variable_substitution(obj.pop(key))
        if isinstance(obj, list):
            for index, item in enumerate(obj):
                obj[index] = self._variable_substitution(item)
        if isinstance(obj, str):
            if re.match(r"^\$\![a-zA-Z_][a-zA-Z0-9_]*$", obj.strip()) \
                    and obj.strip()[2:] in os.environ:
                return os.environ[obj.strip()[2:]]
        return obj

    def _prepare_context_config(self, config, suite):
        """ Prepare context configuration, e.g.: resolve secret variables, merge config objects """
        context_config = recursive_merge(config["global"], config["suites"].get(suite))
        # Allow to inherit from other suite
        if context_config.get("inherit_from", None) and \
                config["suites"].get(context_config.get("inherit_from"), None):
            context_config = recursive_merge(
                config["suites"].get(context_config.get("inherit_from")), context_config
            )
        # Process depots and load modules
        for _ in range(3):
            self._load_modules(context_config)
            context_config = self._process_depots(context_config)
        # Load config objects
        base_config = self._depot_read_config_object("__base__.yaml")
        project_config = self._depot_read_config_object(
            context_config["settings"].get("load_settings_from", None)
        )
        merge_config = self._depot_read_config_object("__merge__.yaml")
        override_config = self._depot_read_config_object("__override__.yaml")
        # Merge resulting config
        result = base_config
        result = recursive_merge(result, context_config)
        result = recursive_merge(result, project_config)
        result = recursive_merge_existing(result, merge_config)
        result = recursive_merge(result, override_config)
        # Process depots and load modules with resulting config
        for _ in range(3):
            self._load_modules(result)
            result = self._process_depots(result)
        return result

    def _load_modules(self, context_config):
        modules_to_load = list()
        for item in [
                value for key, value in context_config["settings"].items() if \
                key.startswith("load_module_from") or key.startswith("load_modules_from")
        ]:
            if isinstance(item, list):
                modules_to_load.extend(item)
            else:
                modules_to_load.append(item)
        for module_name in modules_to_load:
            if module_name in self.context.modules:
                continue  # Module is already loaded during first iteration
            module_object = depots.get_object(self.context, module_name)
            if module_object is not None:
                sys.meta_path.insert(0, DataModuleLoader(module_object))
                self.context.modules.append(module_name)
                log.info("Loaded module from %s", module_name)

    def _process_depots(self, current_context_config):  # pylint: disable=R0912
        context_config = current_context_config
        # Check depot config section sanity
        if "depots" not in context_config["settings"]:
            context_config["settings"]["depots"] = dict()
        depot_sections = ["secret", "object", "state"]
        for depot_section in depot_sections:
            if depot_section not in context_config["settings"]["depots"]:
                context_config["settings"]["depots"][depot_section] = dict()
        # Support legacy depot configuration
        legacy_depot_names = [
            item for item in list(
                context_config["settings"].get("depots", dict())
            ) if item not in depot_sections
        ]
        legacy_section_map = {
            SecretDepotModel: "secret",
            ObjectDepotModel: "object",
            StateDepotModel: "state"
        }
        for depot_name in legacy_depot_names:
            try:
                depot_class = importlib.import_module(
                    f"dusty.tools.depots.{depot_name}.depot"
                ).Depot
                for depot_type in legacy_section_map:
                    if issubclass(depot_class, depot_type):
                        depot_section = legacy_section_map[depot_type]
                        context_config["settings"]["depots"][depot_section][depot_name] = \
                            context_config["settings"]["depots"][depot_name]
                        log.info("Legacy depot %s added to section %s", depot_name, depot_section)
                context_config["settings"]["depots"].pop(depot_name)
            except:
                log.exception("Failed to process legacy depot %s", depot_name)
        # Make depot instances
        for depot_section in depot_sections:
            for depot_name in list(context_config["settings"]["depots"][depot_section]):
                try:
                    depot_class = importlib.import_module(
                        f"dusty.tools.depots.{depot_name}.depot"
                    ).Depot
                    if depot_class.get_name() in self.context.depots[depot_section]:
                        continue  # Depot already enabled in first iteration
                    depot = depot_class(
                        self.context,
                        context_config["settings"]["depots"][depot_section][depot_name]
                    )
                    self.context.depots[depot_section][depot.get_name()] = depot
                    log.info("Enabled %s depot %s", depot_section, depot_name)
                    if isinstance(depot, SecretDepotModel):
                        self.context.set_meta("depots_resolved_secrets", 0)
                        context_config = self._depot_substitution(context_config)
                        log.info(
                            "Resolved %d secrets from depots",
                            self.context.get_meta("depots_resolved_secrets", 0)
                        )
                except ModuleNotFoundError:
                    log.warning(
                        "Depot %s is not enabled, probably needed module is not loaded yet",
                        depot_name
                    )
                except:
                    log.exception("Failed to enable depot %s", depot_name)
        #
        return context_config

    def _depot_substitution(self, obj):
        """ Allows to use depot secrets inside YAML/JSON config """
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                obj[self._depot_substitution(key)] = \
                    self._depot_substitution(obj.pop(key))
        if isinstance(obj, list):
            for index, item in enumerate(obj):
                obj[index] = self._depot_substitution(item)
        if isinstance(obj, str):
            if re.match(r"^\$\=\S*$", obj.strip()):
                obj_key = obj.strip()[2:]
                obj_value = depots.get_secret(self.context, obj_key)
                if obj_value is not None:
                    self.context.set_meta(
                        "depots_resolved_secrets",
                        self.context.get_meta("depots_resolved_secrets", 0) + 1
                    )
                    return obj_value
        return obj

    def _depot_read_config_object(self, obj):
        result = dict()
        if obj is None:
            return result
        data = depots.get_object(self.context, obj)
        if data is None:
            return result
        try:
            self.context.set_meta("depots_resolved_secrets", 0)
            result = self._depot_substitution(
                self._variable_substitution(
                    yaml.load(
                        os.path.expandvars(data),
                        Loader=yaml.FullLoader
                    )
                )
            )
            log.info("Loaded %s from depots", obj)
            log.debug(
                "Resolved %d object secrets from depots",
                self.context.get_meta("depots_resolved_secrets", 0)
            )
            return result
        except:
            return result

    def _validate_config_base(self, config, suite):
        if config.get(constants.CONFIG_VERSION_KEY, 0) != constants.CURRENT_CONFIG_VERSION:
            log.error("Invalid config version")
            return False
        if "global" not in config:
            config["global"] = dict()
        if "suites" not in config:
            log.error("Suites are not defined")
            return False
        if not config["suites"].get(suite, None):
            log.error("Suite is not defined: %s", suite)
            log.info("Available suites: %s", ", ".join(list(config["suites"])))
            return False
        if "settings" not in config["suites"][suite]:
            config["suites"][suite]["settings"] = dict()
        return True

    def list_suites(self, config_seed, config_variable, config_file):
        """ List available suites from config """
        config = self._load_config(config_seed, config_variable, config_file)
        if "suites" not in config:
            log.error("Suites are not defined")
            return list()
        return list(config["suites"])

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj), constants.CONFIG_VERSION_KEY, constants.CURRENT_CONFIG_VERSION
        )
        data_obj.insert(
            len(data_obj), "global", CommentedMap(), comment="Common settings for all suites"
        )
        data_obj.insert(len(data_obj), "suites", CommentedMap(), comment="Test suites")
        global_obj = data_obj["global"]
        global_obj.insert(
            len(global_obj), "settings", CommentedMap(), comment="General config"
        )
        settings_obj = global_obj["settings"]
        settings_obj.insert(
            len(settings_obj), "load_module_from", "module.zip",
            comment="(optional) Load extension module from depot. Can be a string or list"
        )
        settings_obj.insert(
            len(settings_obj), "depots", CommentedMap(), comment="Upstream setting providers config"
        )
        depots_obj = settings_obj["depots"]
        depots_module = importlib.import_module("dusty.tools.depots")
        for _, name, pkg in pkgutil.iter_modules(depots_module.__path__):
            if not pkg:
                continue
            depot = importlib.import_module(
                "dusty.tools.depots.{}.depot".format(name)
            )
            depots_obj.insert(
                len(depots_obj), name, CommentedMap(),
                comment=depot.Depot.get_description()
            )
            depot.Depot.fill_config(depots_obj[name])
