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
    Command: git-clone
"""

import os
import io

from dulwich import porcelain  # pylint: disable=E0401
import paramiko  # pylint: disable=E0401
import paramiko.client  # pylint: disable=E0401
import paramiko.transport  # pylint: disable=E0401

from dusty.tools import log
from dusty.tools import git
from dusty.models.module import ModuleModel
from dusty.models.command import CommandModel


class Command(ModuleModel, CommandModel):
    """ Generate sample config """

    def __init__(self, argparser):
        """ Initialize command instance, add arguments """
        super().__init__()
        argparser.add_argument(
            "-r", "--repository", dest="source",
            help="source git repository",
            type=str
        )
        argparser.add_argument(
            "-t", "--target", dest="target",
            help="target directory",
            type=str
        )
        argparser.add_argument(
            "-b", "--branch", dest="branch",
            help="repository branch",
            type=str, default="master"
        )
        argparser.add_argument(
            "-l", "--lightweight", dest="depth",
            help="limit clone depth",
            type=int
        )
        argparser.add_argument(
            "-u", "--username", dest="username",
            help="username",
            type=str
        )
        argparser.add_argument(
            "-p", "--password", dest="password",
            help="password",
            type=str
        )
        argparser.add_argument(
            "-k", "--key", dest="key",
            help="SSH key file",
            type=str
        )
        argparser.add_argument(
            "-K", "--key-data", dest="key_data",
            help="SSH key data",
            type=str
        )
        argparser.add_argument(
            "--username-variable", dest="username_variable",
            help="environment variable with username",
            type=str, default="GIT_LOGIN"
        )
        argparser.add_argument(
            "--password-variable", dest="password_variable",
            help="environment variable with password",
            type=str, default="GIT_PASSWORD"
        )
        argparser.add_argument(
            "--key-variable", dest="key_variable",
            help="environment variable with path to SSH key",
            type=str, default="GIT_KEY"
        )
        argparser.add_argument(
            "--key-data-variable", dest="key_data_variable",
            help="environment variable with SSH key data",
            type=str, default="GIT_KEY_DATA"
        )


    def execute(self, args):
        """ Run the command """
        log.debug("Starting")
        # Check args
        if not args.source or not args.target:
            log.error("Please specify source and target.")
            return
        # Apply patches
        git.apply_patches()
        # Fill args
        depth = None
        if args.depth:
            depth = args.depth
        # Prepare auth
        auth_args = dict()
        # Take from env variables
        if args.username_variable and args.username_variable in os.environ:
            auth_args["username"] = os.environ[args.username_variable]
            os.environ["USERNAME"] = os.environ[args.username_variable]
        if args.password_variable and args.password_variable in os.environ:
            auth_args["password"] = os.environ[args.password_variable]
        if args.key_variable and args.key_variable in os.environ:
            auth_args["key_filename"] = os.environ[args.key_variable]
        if args.key_data_variable and args.key_data_variable in os.environ:
            key_data_str = os.environ[args.key_data_variable].replace("|", "\n")
            key_data_password = None
            if args.password_variable and args.password_variable in os.environ:
                key_data_password = os.environ[args.password_variable]
            #
            pkey = git.get_pkey_from_data(key_data_str, key_data_password)
            if pkey is None:
                log.warning("Failed to load key from data")
            else:
                auth_args["key_filename"] = pkey
        # Take from commandline parameters
        if args.username:
            auth_args["username"] = args.username
            os.environ["USERNAME"] = args.username
        if args.password:
            auth_args["password"] = args.password
        if args.key:
            auth_args["key_filename"] = args.key
        if args.key_data:
            key_data_str = args.key_data.replace("|", "\n")
            key_data_password = None
            if args.password:
                key_data_password = args.password
            #
            pkey = git.get_pkey_from_data(key_data_str, key_data_password)
            if pkey is None:
                log.warning("Failed to load key from data")
            else:
                auth_args["key_filename"] = pkey
        # Clone repository
        log.info("Cloning repository %s into %s", args.source, args.target)
        repository = porcelain.clone(
            args.source, args.target,
            checkout=False, depth=depth,
            errstream=log.DebugLogStream(),
            **auth_args
        )
        # Checkout branch
        log.info("Checking out branch %s", args.branch)
        branch = args.branch.encode("utf-8")
        repository[b"refs/heads/" + branch] = repository[b"refs/remotes/origin/" + branch]
        repository.refs.set_symbolic_ref(b"HEAD", b"refs/heads/" + branch)
        repository.reset_index(repository[b"HEAD"].tree)

    @staticmethod
    def get_name():
        """ Command name """
        return "git-clone"

    @staticmethod
    def get_description():
        """ Command help message (description) """
        return "clone remote git repository"
