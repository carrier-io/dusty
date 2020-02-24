#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,C0103,C0301,W0702

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
    Dusty setup script
"""

import pkgutil
import importlib
import subprocess

from setuptools import setup, find_packages

with open("README.md") as f:
    long_description = f.read()

with open("requirements.txt") as f:
    required_dependencies = f.read().splitlines()

console_scripts = ["dusty = dusty.main:main"]
legacy_scripts = "dusty.commands.legacy"
legacy_scripts_path = importlib.import_module(legacy_scripts).__path__
for _, name, _ in pkgutil.iter_modules(legacy_scripts_path):
    console_scripts.append("{name} = {module}.{name}:main".format(
        module=legacy_scripts, name=name
    ))

version = "2.0"
try:
    tag = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"])
    version = f"{version}+git.{tag.decode('utf-8').strip()}"
except:
    pass

setup(
    name="dusty",
    version=version,
    license="Apache License 2.0",
    author="Carrier team",
    author_email="artem_rozumenko@epam.com",
    url="https://github.com/carrier-io/dusty",
    description="Framework to execute various security tools and convert output to common unified format",
    long_description=long_description,
    packages=find_packages(),
    include_package_data=True,
    install_requires=required_dependencies,
    entry_points={"console_scripts": console_scripts},
)
