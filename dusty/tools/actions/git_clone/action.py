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
    Clone git repository
"""

import os
import io
import shutil
import getpass

import dulwich  # pylint: disable=E0401
from dulwich import refs  # pylint: disable=E0401
from dulwich import porcelain  # pylint: disable=E0401
from dulwich.contrib.paramiko_vendor import ParamikoSSHVendor  # pylint: disable=E0401

import paramiko  # pylint: disable=E0401
import paramiko.client  # pylint: disable=E0401
import paramiko.transport  # pylint: disable=E0401

from dusty.commands.git_clone import _dulwich_repo_get_default_identity  # pylint: disable=E0401
from dusty.commands.git_clone import _paramiko_transport_verify_key  # pylint: disable=E0401
from dusty.commands.git_clone import _paramiko_client_SSHClient_auth  # pylint: disable=E0401

from dusty.models.action import ActionModel
from dusty.tools import log


class Action(ActionModel):
    """ Action: clone git repository """

    def __init__(self, context, config):
        """ Initialize action instance """
        super().__init__()
        self.context = context
        self.validate_config(config)
        self.config = config

    def run(self):
        """ Run action """
        # Patch dulwich to work without valid UID/GID
        dulwich.repo.__original__get_default_identity = dulwich.repo._get_default_identity  # pylint: disable=W0212
        dulwich.repo._get_default_identity = _dulwich_repo_get_default_identity  # pylint: disable=W0212
        # Patch dulwich to use paramiko SSH client
        dulwich.client.get_ssh_vendor = ParamikoSSHVendor
        # Patch paramiko to skip key verification
        paramiko.transport.Transport._verify_key = _paramiko_transport_verify_key  # pylint: disable=W0212
        # Set USERNAME if needed
        try:
            getpass.getuser()
        except:  # pylint: disable=W0702
            os.environ["USERNAME"] = "git"
        # Get options
        source = self.config.get("source")
        target = self.config.get("target")
        branch = self.config.get("branch", "master")
        depth = self.config.get("depth", None)
        # Prepare auth
        auth_args = dict()
        if self.config.get("username", None) is not None:
            auth_args["username"] = self.config.get("username")
        if self.config.get("password", None) is not None:
            auth_args["password"] = self.config.get("password")
        if self.config.get("key", None) is not None:
            auth_args["key_filename"] = self.config.get("key")
        if self.config.get("key_data", None) is not None:
            key_obj = io.StringIO(self.config.get("key_data").replace("|", "\n"))
            password = self.config.get("password")
            pkey = paramiko.RSAKey.from_private_key(key_obj, password)
            # Patch paramiko to use our key
            paramiko.client.SSHClient._auth = _paramiko_client_SSHClient_auth(  # pylint: disable=W0212
                paramiko.client.SSHClient._auth, pkey  # pylint: disable=W0212
            )
        # Clone repository
        log.info("Cloning repository %s into %s", source, target)
        repository = porcelain.clone(
            source, target, checkout=False, depth=depth, errstream=log.DebugLogStream(), **auth_args
        )
        # Get current HEAD tree (default branch)
        try:
            head_tree = repository[b"HEAD"]
        except:  # pylint: disable=W0702
            head_tree = None
        # Get target tree (requested branch)
        branch_b = branch.encode("utf-8")
        try:
            target_tree = repository[b"refs/remotes/origin/" + branch_b]
        except:  # pylint: disable=W0702
            target_tree = None
        # Checkout branch
        if target_tree is not None:
            log.info("Checking out branch %s", branch)
            repository[b"refs/heads/" + branch_b] = repository[b"refs/remotes/origin/" + branch_b]
            repository.refs.set_symbolic_ref(b"HEAD", b"refs/heads/" + branch_b)
            repository.reset_index(repository[b"HEAD"].tree)
        elif head_tree is not None:
            try:
                default_branch_name = repository.refs.follow(b"HEAD")[0][1]
                if default_branch_name.startswith(refs.LOCAL_BRANCH_PREFIX):
                    default_branch_name = default_branch_name[len(refs.LOCAL_BRANCH_PREFIX):]
                default_branch_name = default_branch_name.decode("utf-8")
                log.warning(
                    "Branch %s was not found. Checking out default branch %s",
                    branch, default_branch_name
                )
            except:  # pylint: disable=W0702
                log.warning("Branch %s was not found. Trying to check out default branch", branch)
            try:
                repository.reset_index(repository[b"HEAD"].tree)
            except:  # pylint: disable=W0702
                log.exception("Failed to checkout default branch")
        else:
            log.error("Branch %s was not found and default branch is not set. Skipping checkout")
        # Delete .git if requested
        if self.config.get("delete_git_dir", False):
            log.info("Deleting .git directory")
            shutil.rmtree(os.path.join(target, ".git"))

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj), "source", "git@github.com:carrier-io/dusty.git",
            comment="Source repository (SSH or HTTPS URL)"
        )
        data_obj.insert(
            len(data_obj), "target", "/data/code",
            comment="Target directory"
        )
        data_obj.insert(
            len(data_obj), "branch", "master",
            comment="(optional) Branch to checkout. Default: master)"
        )
        data_obj.insert(
            len(data_obj), "depth", 1,
            comment="(optional) Limit clone depth (for lightweight clone)"
        )
        data_obj.insert(
            len(data_obj), "username", "some_username",
            comment="(optional) Username for auth"
        )
        data_obj.insert(
            len(data_obj), "password", "SomePassword",
            comment="(optional) Password for auth"
        )
        data_obj.insert(
            len(data_obj), "key", "/path/to/ssh.key",
            comment="(optional) Path to SSH private key for auth"
        )
        data_obj.insert(
            len(data_obj), "key_data", "--- SSHKeyData ---|Goes Here|--- End of SSHKeyData|",
            comment="(optional) SSH private key data for auth. Replace line breaks with '|'"
        )
        data_obj.insert(
            len(data_obj), "delete_git_dir", False,
            comment="(optional) Remove .git directory after checkout"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["source", "target"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def get_name():
        """ Module name """
        return "git_clone"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "Clone git repository"
