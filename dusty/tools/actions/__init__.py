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
    Action tools
"""

import pkgutil
import importlib

from ruamel.yaml.comments import CommentedMap  # pylint: disable=E0401

from dusty.tools import log


def run(context):
    """ Run actions defined in context config """
    log.debug("Running actions for current context")
    # Check context settings
    if "actions" not in context.config:
        context.config["actions"] = dict()
    # Run actions
    for action_name in list(context.config["actions"]):
        try:
            action = importlib.import_module(
                f"dusty.tools.actions.{action_name}.action"
            ).Action(
                context,
                context.config["actions"][action_name]
            )
            context.actions[action.get_name()] = action
            log.info("Running action %s", action_name)
            action.run()
        except:  # pylint: disable=W0702
            log.exception("Failed to run action %s", action_name)


def post_run(context):
    """ Run post-actions defined in context config """
    log.debug("Running post-actions for current context")
    # Check context settings
    if "post_actions" not in context.config:
        context.config["post_actions"] = dict()
    # Run post-actions
    for action_name in list(context.config["post_actions"]):
        try:
            action = importlib.import_module(
                f"dusty.tools.actions.{action_name}.action"
            ).Action(
                context,
                context.config["post_actions"][action_name]
            )
            context.post_actions[action.get_name()] = action
            log.info("Running post-action %s", action_name)
            action.run()
        except:  # pylint: disable=W0702
            log.exception("Failed to run post-action %s", action_name)


def fill_config(data_obj):
    """ Make sample config """
    actions_module = importlib.import_module("dusty.tools.actions")
    for _, name, pkg in pkgutil.iter_modules(actions_module.__path__):
        if not pkg:
            continue
        action = importlib.import_module(
            "dusty.tools.actions.{}.action".format(name)
        )
        data_obj.insert(
            len(data_obj), name, CommentedMap(),
            comment=action.Action.get_description()
        )
        action.Action.fill_config(data_obj[name])
