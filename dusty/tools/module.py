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
    Module tools
"""

import os
import io
import zipfile
import importlib


class DataModuleLoader(importlib.abc.MetaPathFinder):
    """ Allows to load modules from ZIP in-memory data """

    def __init__(self, module_data):
        self.storage = zipfile.ZipFile(io.BytesIO(module_data))
        self.storage_files = [item.filename for item in self.storage.filelist]

    def _fullname_to_filename(self, fullname):
        base = fullname.replace(".", os.sep)
        # Try module directory
        filename = os.path.join(base, "__init__.py")
        if filename in self.storage_files:
            return filename, True
        # Try module file
        filename = f"{base}.py"
        if filename in self.storage_files:
            return filename, False
        # Not found
        return None, None

    def find_spec(self, fullname, path, target=None):  # pylint: disable=W0613
        """ Find spec for new module """
        filename, is_package = self._fullname_to_filename(fullname)
        if filename is None:
            return None
        return importlib.machinery.ModuleSpec(
            fullname, self, origin=filename, is_package=is_package
        )

    def create_module(self, spec):  # pylint: disable=W0613,R0201
        """ Create new module """
        return None

    def exec_module(self, module):
        """ Execute new module """
        module.__file__ = module.__spec__.origin
        with self.storage.open(module.__file__, "r") as file:
            exec(file.read(), module.__dict__)  # pylint: disable=W0122

    def get_data(self, path):
        """ Read data resource """
        try:
            with self.storage.open(path, "r") as file:
                data = file.read()
            return data
        except:
            raise OSError("Resource not found")
