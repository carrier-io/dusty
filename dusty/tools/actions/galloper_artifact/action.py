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
    Clone git repository
"""

import os
import io
import zipfile

import requests  # pylint: disable=E0401

from dusty.models.action import ActionModel
from dusty.tools import log


class Action(ActionModel):
    """ Action: clone git repository """

    def __init__(self, context, config):
        """ Initialize action instance """
        super().__init__()
        self.context = context
        self.validate_config(config)
        self.config = config

    def run(self):
        """ Run action """
        log.info("Getting code from Galloper")
        # Get options
        bucket = self.config.get("bucket")
        srcobj = self.config.get("object")
        target = self.config.get("target")
        # Make request
        headers = dict()
        if os.environ.get("token"):
            headers["Authorization"] = f"Bearer {os.environ.get('token')}"
        #
        obj_url = f"{os.environ.get('galloper_url')}/api/v1/artifacts/artifact/" \
                   f"{os.environ.get('project_id')}/{bucket}/{srcobj}"
        data = requests.get(
            obj_url,
            headers=headers,
            verify=self.config.get("ssl_verify", False),
        ).content
        # Extract data
        os.makedirs(target, exist_ok=True)
        src_zip = zipfile.ZipFile(io.BytesIO(data))
        src_zip.extractall(target)
        # Delete artifact if requested
        if self.config.get("delete", False):
            delete_url = f"{os.environ.get('galloper_url')}/api/v1/artifacts/artifact/" \
                          f"{os.environ.get('project_id')}/{bucket}/{srcobj}"
            requests.delete(
                delete_url,
                headers=headers,
                verify=self.config.get("ssl_verify", False),
            )

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj), "bucket", "sast",
            comment="Source bucket"
        )
        data_obj.insert(
            len(data_obj), "object", "source.zip",
            comment="Source object"
        )
        data_obj.insert(
            len(data_obj), "target", "/tmp/code",
            comment="Target directory"
        )
        data_obj.insert(
            len(data_obj), "delete", False,
            comment="Delete artifact from Galloper"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["bucket", "object", "target"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def get_name():
        """ Module name """
        return "galloper_artifact"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "Get code from Galloper"
