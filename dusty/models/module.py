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
    Generic module model
"""


class ModuleModel:
    """ Module base class """

    @staticmethod
    def get_name():
        """ Module name """
        raise NotImplementedError()

    @staticmethod
    def get_description():
        """ Module description or help message """
        raise NotImplementedError()

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """

    @staticmethod
    def validate_config(config):
        """ Validate config """


class DependentModuleModel(ModuleModel):  # pylint: disable=I0011,W0223
    """ Dependent module base class """

    @staticmethod
    def depends_on():
        """ Return required depencies """
        return list()

    @staticmethod
    def run_after():
        """ Return optional depencies """
        return list()
