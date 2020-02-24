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
    HashiCorp Vault depot
"""

import hvac  # pylint: disable=E0401

from dusty.models.depot import SecretDepotModel
from dusty.tools import log


class Depot(SecretDepotModel):
    """ HashiCorp Vault depot class """

    def __init__(self, context, config):
        """ Initialize depot instance """
        super().__init__()
        self.context = context
        self.validate_config(config)
        self.config = config
        self.client = self._create_vault_client()
        self.secrets = self._get_secrets()

    def _create_vault_client(self):
        client = hvac.Client(
            url=self.config["url"],
            verify=self.config.get("ssl_verify", False),
            namespace=self.config.get("namespace", None)
        )
        if "auth_token" in self.config:
            client.token = self.config["auth_token"]
        if "auth_username" in self.config:
            client.auth_userpass(
                self.config.get("auth_username"), self.config.get("auth_password", "")
            )
        if "auth_role_id" in self.config:
            client.auth_approle(
                self.config.get("auth_role_id"), self.config.get("auth_secret_id", "")
            )
        if not client.is_authenticated():
            error = "Vault authentication failed"
            log.error(error)
            raise ValueError(error)
        return client

    def _get_secrets(self):
        return self.client.secrets.kv.v2.read_secret_version(
            path=self.config.get("secrets_path", "carrier-secrets"),
            mount_point=self.config.get("secrets_mount_point", "carrier-kv")
        ).get("data", dict()).get("data", dict())

    def get_secret(self, key):
        """ Get secret by key """
        if key in self.secrets:
            return self.secrets[key]
        return None

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj), "url", "https://vault.example.com:8200", comment="Vault URL"
        )
        data_obj.insert(
            len(data_obj), "secrets_path", "carrier-kv",
            comment="Secrets path"
        )
        data_obj.insert(
            len(data_obj), "secrets_mount_point", "secret",
            comment="(optional) Secrets KV V2 mount point"
        )
        data_obj.insert(
            len(data_obj), "namespace", "your/namespace",
            comment="(optional) Vault namespace"
        )
        data_obj.insert(
            len(data_obj), "ssl_verify", True,
            comment="(optional) Verify SSL certificate: True, False or path to CA bundle"
        )
        data_obj.insert(
            len(data_obj), "auth_token", "VAULT_TOKEN_VALUE",
            comment="(optional) Auth via token"
        )
        data_obj.insert(
            len(data_obj), "auth_username", "vault_username_value",
            comment="(optional) Auth via username/password"
        )
        data_obj.insert(
            len(data_obj), "auth_password", "vault_password_value",
            comment="(optional) Auth via username/password"
        )
        data_obj.insert(
            len(data_obj), "auth_role_id", "vault_approle_id_value",
            comment="(optional) Auth via approle id/secret id"
        )
        data_obj.insert(
            len(data_obj), "auth_secret_id", "vault_approle_secret_id_value",
            comment="(optional) Auth via approle id/secret id"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["url"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def get_name():
        """ Module name """
        return "vault"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "HashiCorp Vault depot"
