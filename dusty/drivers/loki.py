#!/usr/bin/python3
# coding=utf-8
# pylint: disable=W1401,R0903,E0401,C0411

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
    Loki logging support
"""

import logging
import logging_loki

from queue import Queue


def enable_loki_logging(default_config):
    """ Start logging to Loki """

    if not default_config.get("loki", None):
        return

    loki_url = default_config["loki"].get("url", None)
    if not loki_url:
        logging.warning("No Loki URL in config. Skipping Loki logging")
        return

    loki_username = default_config["loki"].get("username", None)
    loki_password = default_config["loki"].get("password", None)

    auth = None
    if loki_username and loki_password:
        auth = (loki_username, loki_password)

    if default_config["loki"].get("async", False):
        mode = "async"
        handler = logging_loki.LokiQueueHandler(
            Queue(-1),
            url=loki_url,
            tags={"project": default_config.get("project_name", "unknown")},
            auth=auth,
        )
    else:
        mode = "sync"
        handler = logging_loki.LokiHandler(
            url=loki_url,
            tags={"project": default_config.get("project_name", "unknown")},
            auth=auth,
        )

    logging.getLogger("").addHandler(handler)
    logging.info("Enabled Loki logging in %s mode", mode)
