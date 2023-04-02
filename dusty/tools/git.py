#!/usr/bin/python3
# coding=utf-8

#   Copyright 2023 getcarrier.io
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
    Git tools
"""

import io
import os
import shutil
import getpass

from dulwich import refs, repo, porcelain, client  # pylint: disable=E0401
from dulwich.contrib.paramiko_vendor import ParamikoSSHVendor  # pylint: disable=E0401

import paramiko  # pylint: disable=E0401
import paramiko.transport  # pylint: disable=E0401
from paramiko import SSHException, Message  # pylint: disable=E0401
from paramiko.rsakey import RSAKey  # pylint: disable=E0401
from paramiko.dsskey import DSSKey  # pylint: disable=E0401
from paramiko.ecdsakey import ECDSAKey  # pylint: disable=E0401
from paramiko.ed25519key import Ed25519Key  # pylint: disable=E0401

from dusty.tools import log


def apply_patches():
    """ Patch dulwich and paramiko """
    # Set USERNAME if needed
    try:
        getpass.getuser()
    except:  # pylint: disable=W0702
        os.environ["USERNAME"] = "git"
    # Patch dulwich to work without valid UID/GID
    repo._get_default_identity = patched_repo_get_default_identity(repo._get_default_identity)  # pylint: disable=W0212
    # Patch dulwich to use paramiko SSH client
    client.get_ssh_vendor = ParamikoSSHVendor
    # Patch paramiko to skip key verification
    paramiko.transport.Transport._verify_key = patched_paramiko_transport_verify_key  # pylint: disable=W0212
    # Patch paramiko to support direct pkey usage
    paramiko.client.SSHClient._auth = patched_paramiko_client_SSHClient_auth(paramiko.client.SSHClient._auth)  # pylint: disable=C0301,W0212


def patched_repo_get_default_identity(original_repo_get_default_identity):
    """ Allow to run without valid identity """
    def patched_function():
        try:
            return original_repo_get_default_identity()
        except:  # pylint: disable=W0702
            return ("Git User", "git@localhost")
    return patched_function


def patched_paramiko_transport_verify_key(self, host_key, sig):  # pylint: disable=W0613
    """ Only get key info, no deep verification """
    key = self._key_info[self.host_key_type](Message(host_key))  # pylint: disable=W0212
    if key is None:
        raise SSHException("Unknown host key type")
    # Patched: no more checks are done here
    self.host_key = key


def patched_paramiko_client_SSHClient_auth(original_auth):  # pylint: disable=C0103
    """ Allow to pass prepared pkey in key_filename(s) """
    def patched_function(  # pylint: disable=R0913
            self, username, password, pkey, key_filenames, allow_agent, look_for_keys,  # pylint: disable=W0613
            gss_auth, gss_kex, gss_deleg_creds, gss_host, passphrase,
    ):
        if isinstance(key_filenames, list) and len(key_filenames) == 1 and \
                is_premade_pkey(key_filenames[0]):
            target_pkey = key_filenames[0]
            target_key_filenames = list()
            return original_auth(
                self,
                username, password, target_pkey, target_key_filenames, allow_agent, look_for_keys,
                gss_auth, gss_kex, gss_deleg_creds, gss_host, passphrase,
            )
        if is_premade_pkey(key_filenames):
            target_pkey = key_filenames
            target_key_filenames = list()
            return original_auth(
                self,
                username, password, target_pkey, target_key_filenames, allow_agent, look_for_keys,
                gss_auth, gss_kex, gss_deleg_creds, gss_host, passphrase,
            )
        return original_auth(
            self,
            username, password, pkey, key_filenames, allow_agent, look_for_keys,
            gss_auth, gss_kex, gss_deleg_creds, gss_host, passphrase,
        )
    return patched_function


def is_premade_pkey(target_object):
    """ Check if this is pre-made PKey-type object """
    for target_class in (RSAKey, DSSKey, ECDSAKey, Ed25519Key):
        if isinstance(target_object, target_class):
            return True
    #
    return False


def get_pkey_from_data(key_data, key_password=None):
    """ Make PKey object """
    for target_class in (RSAKey, DSSKey, ECDSAKey, Ed25519Key):
        try:
            key_obj = io.StringIO(key_data)
            pkey = target_class.from_private_key(key_obj, key_password)
            log.debug("Loaded PKey as %s", target_class.__name__)
            return pkey
        except:  # pylint: disable=W0702
            log.debug("Could not load PKey as %s", target_class.__name__)
    #
    return None
