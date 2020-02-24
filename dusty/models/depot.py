#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,R0201,W0613

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
    Depot models
"""
from dusty.models.module import ModuleModel
from dusty.models.meta import MetaModel


class SecretDepotModel(ModuleModel, MetaModel):  # pylint: disable=W0223
    """ SecretDepot base class """

    def get_secret(self, key):
        """ Get secret by key """
        return None


class ObjectDepotModel(ModuleModel, MetaModel):  # pylint: disable=W0223
    """ ObjectDepot base class """

    def get_object(self, key):
        """ Get object by key """
        return None

    def put_object(self, key, data):
        """ Put object by key """
        raise RuntimeError("Operation is not supported by this depot")


class StateDepotModel(ModuleModel, MetaModel):  # pylint: disable=W0223
    """ StateDepot base class """

    def load_state(self, state_key):
        """ Load state by key """
        return None

    def save_state(self, state_key, state_data):
        """ Save state by key """
        raise RuntimeError("Operation is not supported by this depot")
