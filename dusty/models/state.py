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
    State helper
"""

import uuid

from dusty.tools import log, depots
from dusty.models.meta import MetaModel


class StateModel(MetaModel):
    """ Holds context state """

    def __init__(self, context):
        """ Initialize state instance """
        super().__init__()
        self.context = context
        self.state_key = None
        self.storage = dict()

    def get_state_key(self):
        """ Derive context key from context """
        if self.state_key is None:
            if self.context.config.get("settings", dict()).get("load_context_from", None):
                self.state_key = self.context.config["settings"]["load_context_from"]
            else:
                descriptor = "UUID5-URL-{}-{}-{}-{}-{}-{}".format(
                    self.context.get_meta("project_name", "UnnamedProject"),
                    self.context.get_meta("project_description", "Undescribed Project"),
                    self.context.get_meta("environment_name", "default"),
                    self.context.get_meta("testing_type", "DSAST"),
                    self.context.get_meta("scan_type", "scanning"),
                    self.context.suite
                )
                self.state_key = str(uuid.uuid5(uuid.NAMESPACE_URL, descriptor))
        return self.state_key

    def load(self, state_key=None):
        """ Load state """
        if state_key is None:
            state_key = self.get_state_key()
        try:
            state_data = depots.load_state(self.context, state_key)
            if isinstance(state_data, dict):
                self.storage = state_data
                log.info("Loaded state for %s", state_key)
        except:  # pylint: disable=W0702
            log.exception("Failed to load state")

    def save(self, state_key=None):
        """ Save state """
        if state_key is None:
            state_key = self.get_state_key()
        try:
            result = depots.save_state(self.context, state_key, self.storage)
            if result is True:
                log.info("Saved state for %s", state_key)
        except:  # pylint: disable=W0702
            log.exception("Failed to save state")

    def get(self, key, default=None):
        """ Get state item by key """
        return self.storage.get(key, default)

    def set(self, key, value):
        """ Set state item by key """
        self.storage[key] = value

    def reset(self):
        """ Clear state """
        self.state_key = None
        self.storage = dict()
