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
    MinIO depot
"""

import io
import minio  # pylint: disable=E0401
import urllib3  # pylint: disable=E0401

from dusty.models.depot import ObjectDepotModel
from dusty.tools import log


class Depot(ObjectDepotModel):
    """ MinIO depot class """

    def __init__(self, context, config):
        """ Initialize depot instance """
        super().__init__()
        self.context = context
        self.validate_config(config)
        self.config = config
        self.client = self._create_minio_client()

    def _create_minio_client(self):
        http_client = None
        if not self.config.get("ssl_verify", False):
            http_client = urllib3.PoolManager(
                timeout=urllib3.Timeout.DEFAULT_TIMEOUT,
                cert_reqs="CERT_NONE",
                maxsize=10,
                retries=urllib3.Retry(
                    total=5,
                    backoff_factor=0.2,
                    status_forcelist=[500, 502, 503, 504]
                )
            )
        if isinstance(self.config.get("ssl_verify", False), str):
            http_client = urllib3.PoolManager(
                timeout=urllib3.Timeout.DEFAULT_TIMEOUT,
                cert_reqs="CERT_REQUIRED",
                ca_certs=self.config.get("ssl_verify"),
                maxsize=10,
                retries=urllib3.Retry(
                    total=5,
                    backoff_factor=0.2,
                    status_forcelist=[500, 502, 503, 504]
                )
            )
        client = minio.Minio(
            endpoint=self.config["endpoint"],
            access_key=self.config.get("access_key", None),
            secret_key=self.config.get("secret_key", None),
            secure=self.config.get("secure", True),
            region=self.config.get("region", None),
            http_client=http_client
        )
        # Test client auth
        client.bucket_exists(self.config.get("bucket", "carrier"))
        return client

    def get_object(self, key):
        """ Get object by key """
        try:
            return self.client.get_object(self.config.get("bucket", "carrier"), key).read()
        except:  # pylint: disable=W0702
            return None

    def put_object(self, key, data):
        """ Put object by key """
        try:
            if isinstance(data, str):
                data = data.encode("utf-8")
            data_obj = io.BytesIO(data)
            self.client.put_object(self.config.get("bucket", "carrier"), key, data_obj, len(data))
            return True
        except:  # pylint: disable=W0702
            log.exception("Failed to put object")
            return False

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj), "endpoint", "minio.example.com:9000",
            comment="S3 object storage endpoint"
        )
        data_obj.insert(
            len(data_obj), "bucket", "carrier",
            comment="Carrier bucket name"
        )
        data_obj.insert(
            len(data_obj), "access_key", "ACCESSKEYVALUE",
            comment="(optional) Access key for the object storage endpoint"
        )
        data_obj.insert(
            len(data_obj), "secret_key", "SECRETACCESSKEYVALUE",
            comment="(optional) Secret key for the object storage endpoint."
        )
        data_obj.insert(
            len(data_obj), "secure", True,
            comment="(optional) Set this value to True to enable secure (HTTPS) access"
        )
        data_obj.insert(
            len(data_obj), "ssl_verify", True,
            comment="(optional) Verify SSL certificate: True, False or path to CA bundle"
        )
        data_obj.insert(
            len(data_obj), "region", "us-east-1",
            comment="(optional) Set this value to override automatic bucket location discovery"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["endpoint"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def get_name():
        """ Module name """
        return "minio"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "MinIO depot"
