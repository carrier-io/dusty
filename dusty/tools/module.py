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
import pkg_resources

from dusty.tools import log


class LocalModuleLoader(importlib.abc.MetaPathFinder):
    """ Allows to load modules from local data """

    def __init__(self, module_name, module_path):
        self.module_name = module_name
        self.module_path = module_path

    def _fullname_to_filename(self, fullname):
        base = fullname.replace(".", os.sep)
        base = os.path.join(self.module_path, base)
        # Try module directory
        filename = os.path.join(base, "__init__.py")
        if os.path.isfile(filename):
            return filename, True
        # Try module file
        filename = f"{base}.py"
        if os.path.isfile(filename):
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
        with open(module.__file__, "rb") as file:
            code_filename = os.path.relpath(module.__file__, self.module_path)
            code = compile(
                source=file.read(),
                filename=f"{self.module_name}:{code_filename}",
                mode="exec",
                dont_inherit=True,
            )
            exec(code, module.__dict__)  # pylint: disable=W0122

    def get_data(self, path):
        """ Read data resource """
        try:
            with open(path, "rb") as file:
                data = file.read()
            return data
        except Exception as exception:
            raise OSError("Resource not found") from exception


class LocalModuleProvider(pkg_resources.NullProvider):  # pylint: disable=W0223
    """ Allows to load resources from local data """

    def __init__(self, module):
        pkg_resources.NullProvider.__init__(self, module)
        self.module = module
        self.module_name = getattr(module, "__name__", "")

    def _has(self, path):
        return os.path.exists(path)


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
            code = compile(
                source=file.read(),
                filename=f"[module]:{module.__file__}",
                mode="exec",
                dont_inherit=True,
            )
            exec(code, module.__dict__)  # pylint: disable=W0122

    def get_data(self, path):
        """ Read data resource """
        try:
            with self.storage.open(path, "r") as file:
                data = file.read()
            return data
        except:
            raise OSError("Resource not found")


class DataModuleProvider(pkg_resources.NullProvider):  # pylint: disable=W0223
    """ Allows to load resources from ZIP in-memory data """

    def __init__(self, module):
        pkg_resources.NullProvider.__init__(self, module)
        self.module_name = getattr(module, "__name__", "")

    def _has(self, path):
        return path in self.loader.storage_files
