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
    Processor: false_positive
"""

from json import dumps
from requests import get

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.processor import ProcessorModel

from . import constants


class Processor(DependentModuleModel, ProcessorModel):
    """ Process findings: filter false-positives """

    def __init__(self, context):
        """ Initialize processor instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["processing"][__name__.split(".")[-2]]

    def galloper_connector(self):
        auth = None
        if self.config.get("user") and self.config.get("password"):
            auth = (self.config.get("user"), self.config.get("password"))
        data = {
            "project_name": self.context.get_meta('project_name'),
            "scan_type": self.context.get_meta("testing_type"),
            "app_name": self.context.get_meta("project_description")
        }
        fp_list = get(f'{self.config.get("galloper")}{constants.GALLOPER_API_PATH}',
                      headers={"content-type": "application/json"}, auth=auth,
                      data=dumps(data)).json()
        with open(constants.GALLOPER_FPA_PATH, "w") as f:
            f.write("\n".join(fp_list).strip())
        return constants.GALLOPER_FPA_PATH

    def execute(self):
        """ Run the processor """
        log.info("Processing false-positives")
        if self.config.get("galloper"):
            fp_config_path = self.galloper_connector()
        else:
            fp_config_path = self.config.get("file", constants.DEFAULT_FP_CONFIG_PATH)
        try:
            false_positives = list()
            # Load false positives
            with open(fp_config_path, "r") as file:
                for line in file.readlines():
                    if line.strip():
                        false_positives.append(line.strip())
            # Process findings
            for item in self.context.findings:
                issue_hash = item.get_meta("issue_hash", "<no_hash>")
                if issue_hash in false_positives:
                    item.set_meta("false_positive_finding", True)
        except:  # pylint: disable=W0702
            log.exception("Failed to process false-positives")

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj), "file", "/path/to/false_positive.config",
            comment="File with issue hashes"
        )

    @staticmethod
    def depends_on():
        """ Return required depencies """
        return ["issue_hash"]

    @staticmethod
    def get_name():
        """ Module name """
        return "False-positive"

    @staticmethod
    def get_description():
        """ Module description """
        return "False-positive processor"
