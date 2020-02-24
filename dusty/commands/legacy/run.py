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
    Legacy entry point
"""

import os
import sys

import dusty.main


def main():
    """ Adjust parameters and run main entry """
    sys.argv[0] = "dusty"
    sys.argv.insert(1, "run")
    sys.argv.insert(2, "--call-from-legacy")
    if os.environ.get("debug", False):
        sys.argv.insert(3, "--debug")
    print(f"running: {sys.argv}")
    dusty.main.main()
