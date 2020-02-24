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
    Processor: title_rewriter
"""

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.processor import ProcessorModel
from dusty.models.finding import DastFinding, SastFinding


class Processor(DependentModuleModel, ProcessorModel):
    """ Process findings: rewrite titles after issue hash is injected """

    def __init__(self, context):
        """ Initialize processor instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["processing"][__name__.split(".")[-2]]

    def execute(self):
        """ Run the processor """
        log.info("Rewriting finding titles")
        for item in self.context.findings:
            if isinstance(item, (DastFinding, SastFinding)):
                if item.get_meta("rewrite_title_to", None):
                    item.set_meta("original_title", item.title)
                    item.title = item.get_meta("rewrite_title_to")

    @staticmethod
    def run_after():
        """ Return optional depencies """
        return ["issue_hash"]

    @staticmethod
    def get_name():
        """ Module name """
        return "Finding title rewriter"

    @staticmethod
    def get_description():
        """ Module description """
        return "Rewrites finding titles (if marked by other modules)"
