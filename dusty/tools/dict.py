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
    Dict tools
"""

from collections import OrderedDict


# Taken from https://docs.python.org/3/library/collections.html#ordereddict-examples-and-recipes
class LastUpdatedOrderedDict(OrderedDict):
    """ Store items in the order the keys were last added """

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        super().move_to_end(key)


def recursive_merge(dict_a, dict_b):
    """ Merge dictionaries recursively """
    result = dict()
    for key in set(list(dict_a.keys()) + list(dict_b.keys())):
        if key not in dict_a:
            result[key] = dict_b[key]
        elif key not in dict_b:
            result[key] = dict_a[key]
        elif isinstance(dict_a[key], dict) and isinstance(dict_b[key], dict):
            result[key] = recursive_merge(dict_a[key], dict_b[key])
        else:
            result[key] = dict_b[key]
    return result


def recursive_merge_existing(dict_a, dict_b):
    """ Merge dictionaries recursively (only already existing dicts) """
    result = dict()
    for key in set(list(dict_a.keys()) + list(dict_b.keys())):
        if key not in dict_a:
            if isinstance(dict_b[key], dict):
                continue
            result[key] = dict_b[key]
        elif key not in dict_b:
            result[key] = dict_a[key]
        elif isinstance(dict_a[key], dict) and isinstance(dict_b[key], dict):
            result[key] = recursive_merge_existing(dict_a[key], dict_b[key])
        else:
            if isinstance(dict_a[key], bool) and not isinstance(dict_b[key], bool) and \
                    not dict_a[key]:
                continue
            result[key] = dict_b[key]
    return result
