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
    Reporter model
"""

from dusty.models.meta import MetaModel


class ReporterModel(MetaModel):
    """ Reporter base class """

    def __init__(self):
        super().__init__()
        self.errors = list()

    def get_errors(self):
        """ Get errors """
        return self.errors

    def on_start(self):
        """ Called when testing starts """

    def on_finish(self):
        """ Called when testing ends """

    def on_scanner_start(self, scanner):
        """ Called when scanner starts """

    def on_scanner_finish(self, scanner):
        """ Called when scanner ends """

    def report(self):
        """ Report """

    def flush(self):
        """ Flush """
