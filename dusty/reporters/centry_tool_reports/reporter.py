#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,E0401

#   Copyright 2024 getcarrier.io
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
    Reporter: Centry tool reports
"""

import os
import zipfile
import tempfile

import requests

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.reporter import ReporterModel


class Reporter(DependentModuleModel, ReporterModel):
    """ Report findings from scanners """

    def __init__(self, context):
        """ Initialize reporter instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["reporters"][__name__.split(".")[-2]]

    def report(self):
        """ Report """
        log.info("Sending tool reports to Centry")
        # Get options
        bucket = self.config.get("bucket")
        tgtobj = self.config.get("object")
        source = self.config.get("source")
        # Compress data
        with tempfile.TemporaryFile() as tgt_file:
            with zipfile.ZipFile(tgt_file, "w", zipfile.ZIP_DEFLATED) as zip_file:
                tgt_dir = os.path.abspath(source)
                for dirpath, _, filenames in os.walk(tgt_dir):
                    if dirpath == tgt_dir:
                        rel_dir = ""
                    else:
                        rel_dir = os.path.relpath(dirpath, tgt_dir)
                        zip_file.write(dirpath, arcname=rel_dir)
                    for filename in filenames:
                        zip_file.write(
                            os.path.join(dirpath, filename),
                            arcname=os.path.join(rel_dir, filename)
                        )
            tgt_file.seek(0)
            # Send to Centry
            requests.post(
                f'{self.config["url"]}/api/v1/artifacts/artifacts/{self.config["project_id"]}/{bucket}',  # pylint: disable=C0301
                files={"file": (f"{tgtobj}", tgt_file)},
                headers={"Authorization": f'Bearer {self.config["token"]}'},
                verify=self.config.get("ssl_verify", False),
            )

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj), "bucket", "sast",
            comment="Target bucket"
        )
        data_obj.insert(
            len(data_obj), "object", "target.zip",
            comment="Target object"
        )
        data_obj.insert(
            len(data_obj), "source", "/tmp/intermediates",
            comment="Source directory"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["bucket", "object", "source"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def get_name():
        """ Reporter name """
        return "Centry tool reports"

    @staticmethod
    def get_description():
        """ Reporter description """
        return "Centry REST API tool output reporter"
