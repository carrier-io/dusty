#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011

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
    File depot
"""

import os
import traceback

from dusty.models.depot import ObjectDepotModel
from dusty.tools import log


class Depot(ObjectDepotModel):
    """ MinIO depot class """

    def __init__(self, context, config):
        """ Initialize depot instance """
        super().__init__()
        self.context = context
        self.validate_config(config)
        self.config = config

    def get_object(self, key):
        """ Get object by key """
        try:
            log.debug("Trying to get object '%s' (path = '%s')", key, self.config.get("path"))
            with open(os.path.join(self.config.get("path"), key), "rb") as file:
                data = file.read()
            return data
        except:  # pylint: disable=W0702
            log.debug("Got exception: %s", traceback.format_exc())
            return None

    def put_object(self, key, data):
        """ Put object by key """
        try:
            if isinstance(data, str):
                data = data.encode("utf-8")
            with open(os.path.join(self.config.get("path"), key), "wb") as file:
                file.write(data)
            return True
        except:  # pylint: disable=W0702
            log.exception("Failed to put object")
            return False

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj), "path", "/data",
            comment="Path to store"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["path"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def get_name():
        """ Module name """
        return "file"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "File depot"
