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
    Processor: issue_hash
"""

import os
import os.path
import re
import hashlib

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.processor import ProcessorModel
from dusty.models.finding import DastFinding, SastFinding


class Processor(DependentModuleModel, ProcessorModel):
    """ Process findings: inject issue_hash for compatibility during 1.0->2.0 migration """

    def __init__(self, context):
        """ Initialize processor instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["processing"][__name__.split(".")[-2]]

    def execute(self):
        """ Run the processor """
        log.info("Injecting issue hashes")
        for item in self.context.findings:
            issue_hash = None
            # Legacy code: prepare issue hash
            if isinstance(item, DastFinding):
                title = re.sub('[^A-Za-zА-Яа-я0-9//\\\.\- _]+', '', item.title)  # pylint: disable=W1401
                issue_hash = hashlib.sha256(
                    f'{title}_None_None__'.strip().encode('utf-8')
                ).hexdigest()
            if isinstance(item, SastFinding):
                title = re.sub('[^A-Za-zА-Яа-я0-9//\\\.\- _]+', '', item.title)  # pylint: disable=W1401
                #
                if self.config.get("sast_use_cwe", True):
                    cwe = item.get_meta("legacy.cwe", "None")
                else:
                    cwe = "None"
                #
                if self.config.get("sast_use_line", True):
                    line = item.get_meta("legacy.line", "None")
                else:
                    line = "None"
                #
                if self.config.get("sast_use_file", True):
                    skip_roots = self.config.get("sast_skip_file_roots", None)
                    if isinstance(skip_roots, int) and skip_roots > 0:
                        file_data = item.get_meta("legacy.file", "")
                        data_parts = [part for part in file_data.split(os.sep) if part]
                        file = os.path.join(*data_parts[skip_roots:])
                    else:
                        file = item.get_meta("legacy.file", "")
                else:
                    file = ""
                #
                issue_hash = hashlib.sha256(
                    f'{title}_{cwe}_{line}_{file}_'.strip().encode('utf-8')
                ).hexdigest()
            # Inject issue hash
            if issue_hash:
                item.set_meta("issue_hash", issue_hash)
                if isinstance(item, DastFinding):
                    item.description += f"\n\n**Issue Hash:** {issue_hash}"
                if isinstance(item, SastFinding):
                    item.description[0] += f"\n\n**Issue Hash:** {issue_hash}"

    @staticmethod
    def get_name():
        """ Module name """
        return "Issue hash injector"

    @staticmethod
    def get_description():
        """ Module description """
        return "Injects issue hashes into findings"
