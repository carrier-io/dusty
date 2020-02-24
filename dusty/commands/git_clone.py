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
import getpass

import dulwich  # pylint: disable=E0401
from dulwich import porcelain  # pylint: disable=E0401
from dulwich.contrib.paramiko_vendor import ParamikoSSHVendor  # pylint: disable=E0401
import paramiko  # pylint: disable=E0401
import paramiko.client  # pylint: disable=E0401
import paramiko.transport  # pylint: disable=E0401
from paramiko.ssh_exception import SSHException  # pylint: disable=E0401
from paramiko.message import Message  # pylint: disable=E0401


from dusty.tools import log
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
            key_obj = io.StringIO(os.environ[args.key_data_variable].replace("|", "\n"))
            pkey = paramiko.RSAKey.from_private_key(key_obj)
            # Patch paramiko to use our key
            paramiko.client.SSHClient._auth = _paramiko_client_SSHClient_auth(  # pylint: disable=W0212
                paramiko.client.SSHClient._auth, pkey  # pylint: disable=W0212
            )
        # Take from commandline parameters
        if args.username:
            auth_args["username"] = args.username
            os.environ["USERNAME"] = args.username
        if args.password:
            auth_args["password"] = args.password
        if args.key:
            auth_args["key_filename"] = args.key
        if args.key_data:
            key_obj = io.StringIO(args.key_data.replace("|", "\n"))
            pkey = paramiko.RSAKey.from_private_key(key_obj)
            # Patch paramiko to use our key
            paramiko.client.SSHClient._auth = _paramiko_client_SSHClient_auth(  # pylint: disable=W0212
                paramiko.client.SSHClient._auth, pkey  # pylint: disable=W0212
            )
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


def _dulwich_repo_get_default_identity():
    try:
        return dulwich.repo.__original__get_default_identity()  # pylint: disable=W0212
    except:  # pylint: disable=W0702
        return ("Carrier User", "dusty@localhost")


def _paramiko_transport_verify_key(self, host_key, sig):  # pylint: disable=W0613
    key = self._key_info[self.host_key_type](Message(host_key))  # pylint: disable=W0212
    if key is None:
        raise SSHException('Unknown host key type')
    self.host_key = key


def _paramiko_client_SSHClient_auth(original_auth, forced_pkey):  # pylint: disable=C0103
    def __paramiko_client_SSHClient_auth(  # pylint: disable=C0103,R0913
            self, username, password, pkey, key_filenames, allow_agent, look_for_keys,  # pylint: disable=W0613
            gss_auth, gss_kex, gss_deleg_creds, gss_host, passphrase
        ):
        return original_auth(
            self, username, password, forced_pkey, key_filenames, allow_agent, look_for_keys,
            gss_auth, gss_kex, gss_deleg_creds, gss_host, passphrase
        )
    return __paramiko_client_SSHClient_auth
