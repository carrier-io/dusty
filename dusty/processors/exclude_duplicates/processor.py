#!/usr/bin/python3
# coding=utf-8

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
    Processor: exclude_duplicates
"""

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.processor import ProcessorModel


class Processor(DependentModuleModel, ProcessorModel):
    """ Process findings: exclude findings with same issue hashes """

    def __init__(self, context):
        """ Initialize processor instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["processing"][__name__.split(".")[-2]]

    def execute(self):
        """ Run the processor """
        log.info("Excluding duplicate findings")
        known_hashes = set()
        # Process findings
        for item in self.context.findings:
            issue_hash = item.get_meta("issue_hash", "<no_hash>")
            #
            if issue_hash == "<no_hash>":
                continue
            #
            if issue_hash in known_hashes:
                item.set_meta("excluded_finding", True)
                continue
            #
            known_hashes.add(issue_hash)

    @staticmethod
    def run_after():
        """ Return optional depencies """
        return ["issue_hash"]

    @staticmethod
    def get_name():
        """ Module name """
        return "Exclude duplicates"

    @staticmethod
    def get_description():
        """ Module description """
        return "Excludes findings with same issue hashes"
