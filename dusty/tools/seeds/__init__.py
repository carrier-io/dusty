#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011

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
    Config seed tools
"""

import importlib
import pkgutil

from dusty.tools import log


def unseed(config_seed):
    """ Get config from config seed """
    if ":" not in config_seed:
        log.info("Config seed is empty or invalid, skipping")
        return None
    config_seed_tag = config_seed[:config_seed.find(":")]
    config_seed_data = config_seed[len(config_seed_tag)+1:]
    try:
        seed = importlib.import_module(f"dusty.tools.seeds.{config_seed_tag}.seed")
        return seed.Seed().handle(config_seed_data)
    except:  # pylint: disable=W0702
        log.exception("Failed to unseed config, skipping seed")
        return None
