#!/usr/bin/python3
# coding=utf-8

#   Copyright 2020 getcarrier.io
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
    Processor: ignore_finding
"""

from json import dumps
from requests import get

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.processor import ProcessorModel
from dusty.models.finding import DastFinding, SastFinding

from . import constants


class Processor(DependentModuleModel, ProcessorModel):
    """ Process findings: filter ignored """

    def __init__(self, context):
        """ Initialize processor instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["processing"][__name__.split(".")[-2]]

    def galloper_connector(self):
        auth = None
        headers = {"content-type": "application/json"}
        if self.config.get("user") and self.config.get("password"):
            auth = (self.config.get("user"), self.config.get("password"))
        elif self.config.get("token"):
            headers["Authorization"] = f'bearer {self.config.get("token")}'
        if self.config.get("project_id"):
            galloper_url = constants.GALLOPER_API_PATH.format(project_id=self.config.get("project_id"))
        else:
            galloper_url = constants.LEGACY_GALLOPER_API_PATH
        data = {
            "project_name": self.context.get_meta('project_name'),
            "scan_type": self.context.get_meta("testing_type"),
            "app_name": self.context.get_meta("project_description")
        }
        fp_list = get(f'{self.config.get("galloper")}{galloper_url}',
                      headers=headers, auth=auth,
                      params=data).json()
        with open(constants.GALLOPER_IGN_PATH, "w") as f:
            f.write("\n".join(fp_list).strip())
        return constants.GALLOPER_IGN_PATH

    def execute(self):
        """ Run the processor """
        log.info("Processing ignored findings")
        if self.config.get("galloper"):
            ign_config_path = self.galloper_connector()
        else:
            ign_config_path = self.config.get("file", constants.DEFAULT_IGN_CONFIG_PATH)
        try:
            ignored_findings = dict()
            # Load false positives
            with open(ign_config_path, "r") as file:
                for line in file.readlines():
                    if line.strip():
                        line_data = line.strip()
                        #
                        line_hash = line_data
                        line_comment = None
                        if "#" in line_data:
                            line_hash = line_data.split("#", 1)[0].strip()
                            line_comment = line_data.split("#", 1)[1].strip()
                        #
                        ignored_findings[line_hash] = line_comment
            # Process findings
            for item in self.context.findings:
                issue_hash = item.get_meta("issue_hash", "<no_hash>")
                if issue_hash in ignored_findings:
                    item.set_meta("excluded_finding", True)
                    issue_comment = ignored_findings[issue_hash]
                    if issue_comment is not None:
                        if isinstance(item, DastFinding):
                            item.description = f"**Finding comment:** {issue_comment}\n\n" + \
                                item.description
                        if isinstance(item, SastFinding):
                            item.description[0] = f"**Finding comment:** {issue_comment}\n\n" + \
                                item.description[0]
        except:  # pylint: disable=W0702
            log.exception("Failed to process ignored findings")

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj), "file", "/path/to/ignore.config",
            comment="File with issue hashes"
        )

    @staticmethod
    def depends_on():
        """ Return required depencies """
        return ["issue_hash"]

    @staticmethod
    def get_name():
        """ Module name """
        return "Ignored"

    @staticmethod
    def get_description():
        """ Module description """
        return "Ignored finding processor"
