#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,E0401,W0702,W0703,R0902

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
    Scanner: OWASP ZAP
"""

import os
import re
import sys
import json
import time
import shutil
import base64
import urllib
import tempfile
import traceback
import subprocess
import collections
import pkg_resources

from ruamel.yaml.comments import CommentedSeq
from ruamel.yaml.comments import CommentedMap
from zapv2 import ZAPv2

from dusty.tools import log, status, url
from dusty.models.module import DependentModuleModel
from dusty.models.scanner import ScannerModel
from dusty.models.error import Error

from . import constants
from .parser import parse_findings


class Scanner(DependentModuleModel, ScannerModel):
    """ Scanner class """

    def __init__(self, context):
        """ Initialize scanner instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["scanners"][__name__.split(".")[-3]][__name__.split(".")[-2]]
        self._zap_daemon = None
        self._zap_api = None
        self._zap_context = None
        self._zap_context_name = None
        self._zap_user = None
        self._scan_policy_name = None
        self._scan_policies = None

    def execute(self):
        """ Run the scanner """
        try:
            if self.config.get("exec_side_scenario", None):
                log.warning("ZAP scanning running in experimental mode")
                container = None
                #
                self._start_zap()
                if not self._wait_for_zap_start():
                    log.error("ZAP failed to start")
                    error = Error(
                        tool=self.get_name(),
                        error="ZAP failed to start",
                        details="ZAP daemon failed to start"
                    )
                    self.errors.append(error)
                    return
                #
                log.info("Target: %s", self.config.get("target"))
                #
                self._prepare_context()
                self._setup_scan_policy()
                #
                import docker
                # Start chrome
                log.info("Getting docker client")
                client = docker.from_env()
                #
                log.info("Starting chrome container")
                container = client.containers.run(
                    "getcarrier/dast:poc-chrome-87.0",
                    auto_remove=True,
                    detach=True,
                    network_mode=f"container:{os.environ['HOSTNAME']}",
                )
                #
                log.info("Waiting for chrome to start")
                time.sleep(10.0)
                #
                # Run observer test
                scenario_path = self.config.get("exec_side_scenario")
                with open(scenario_path, "rb") as file:
                    scenario = json.load(file)
                #
                os.environ["STANDALONE"] = "yes"
                os.environ["REMOTE_URL"] = "localhost:4444"
                os.environ["PROXY"] = "http://localhost:8091"
                #
                args = collections.namedtuple(
                    "Namespace", [
                        "aggregation", "browser", "data", "export",
                        "file", "loop", "report", "scenario", "test_id"
                    ]
                )(
                    aggregation="max", browser="chrome_87.0", data="",
                    export=[], file="", loop=1, report=[],
                    scenario=scenario_path, test_id=""
                )
                #
                from selene.support.shared import SharedConfig
                from observer.driver_manager import set_config, set_args, close_driver
                from observer.executors.scenario_executor import execute_scenario
                #
                config = SharedConfig()
                config.base_url = scenario['url']
                set_config(config)
                set_args(args)
                #
                execute_scenario(scenario, args)
                close_driver()
                #
                # Stop chrome
                log.info("Stopping chrome")
                container.stop()
                #
                log.info("Running ZAP active scan")
                self._active_scan()
                #
                log.info("Waiting for ZAP passive scan")
                self._wait_for_passive_scan()
            else:
                self._start_zap()
                if not self._wait_for_zap_start():
                    log.error("ZAP failed to start")
                    error = Error(
                        tool=self.get_name(),
                        error="ZAP failed to start",
                        details="ZAP daemon failed to start"
                    )
                    self.errors.append(error)
                    return
                log.info("Target: %s", self.config.get("target"))
                self._prepare_context()
                self._setup_scan_policy()
                self._spider()
                self._wait_for_passive_scan()
                self._ajax_spider()
                self._wait_for_passive_scan()
                self._active_scan()
                self._wait_for_passive_scan()
        except:
            log.exception("Exception during ZAP scanning")
            error = Error(
                tool=self.get_name(),
                error="Exception during ZAP scanning",
                details=f"```\n{traceback.format_exc()}\n```"
            )
            self.errors.append(error)
        finally:
            try:
                try:
                    # Stop chrome again if needed
                    if container is not None:
                        container.stop()
                except:
                    pass
                # Get report
                log.info("Getting ZAP report")
                zap_report = self._zap_api.core.jsonreport()
                # Parse JSON
                log.info("Processing findings")
                parse_findings(zap_report, self)
            except:
                log.exception("Exception during ZAP findings processing")
                error = Error(
                    tool=self.get_name(),
                    error="Exception during ZAP findings processing",
                    details=f"```\n{traceback.format_exc()}\n```"
                )
                self.errors.append(error)
            self._save_intermediates()
            pkg_resources.cleanup_resources()
            self._stop_zap()

    def _start_zap(self):
        """ Start ZAP daemon, create API client """
        # External ZAP daemon
        if self.config.get("external_zap_daemon", None):
            log.info("Using external ZAP daemon")
            self._zap_api = ZAPv2(
                apikey=self.config.get("external_zap_api_key", "dusty"),
                proxies={
                    "http": self.config.get("external_zap_daemon"),
                    "https": self.config.get("external_zap_daemon")
                }
            )
            return
        # Internal ZAP daemon
        log.info("Starting ZAP daemon")
        bind_host = "127.0.0.1"
        if self.config.get("bind_all_interfaces", True):
            bind_host = "0.0.0.0"
        daemon_out = subprocess.DEVNULL
        if self.config.get("daemon_debug", False):
            daemon_out = sys.stdout
        zap_home_dir = tempfile.mkdtemp()
        log.debug("ZAP home directory: %s", zap_home_dir)
        self._zap_daemon = subprocess.Popen([
            "/usr/bin/java", self.config.get("java_options", "-Xmx1g"),
            "-jar", constants.ZAP_PATH,
            "-dir", zap_home_dir,
            "-daemon", "-port", "8091", "-host", bind_host,
            "-config", "api.key=dusty",
            "-config", "api.addrs.addr.regex=true",
            "-config", "api.addrs.addr.name=.*",
            "-config", "ajaxSpider.browserId=htmlunit"
        ], stdout=daemon_out, stderr=daemon_out)
        self._zap_api = ZAPv2(
            apikey="dusty",
            proxies={
                "http": "http://127.0.0.1:8091",
                "https": "http://127.0.0.1:8091"
            }
        )

    def _wait_for_zap_start(self):
        for _ in range(600):
            try:
                log.info("Started ZAP %s", self._zap_api.core.version)
                return True
            except IOError:
                time.sleep(1)
        return False

    def _save_intermediates(self):
        if self.config.get("save_intermediates_to", None) and self._zap_daemon is None:
            log.info("Saving intermediates")
            base = os.path.join(self.config.get("save_intermediates_to"), __name__.split(".")[-2])
            try:
                # Make directory for artifacts
                os.makedirs(base, mode=0o755, exist_ok=True)
                # Save session
                self._zap_api.core.save_session(os.path.join(base, "zap.session"))
                # Save context
                self._zap_api.context.export_context(
                    self._zap_context_name, os.path.join(base, "zap.context")
                )
                # Copy log
                shutil.copyfile(
                    os.path.join(self._zap_api.core.zap_home_path, "zap.log"),
                    os.path.join(base, "zap.log")
                )
            except:
                log.exception("Failed to save intermediates")

    def _stop_zap(self):
        if self._zap_daemon:
            log.info("Stopping ZAP daemon")
            self._zap_daemon.kill()
            self._zap_daemon.wait()
            self._zap_daemon = None

    def _wait_for_passive_scan(self):
        limit = self.config.get("passive_scan_wait_threshold", 0)
        status.wait_for_completion(
            lambda: int(self._zap_api.pscan.records_to_scan) > limit,
            lambda: int(self._zap_api.pscan.records_to_scan),
            "Passive scan queue: %d items",
            limit=self.config.get("passive_scan_wait_limit", None)
        )

    def _prepare_context(self):  # pylint: disable=R0912
        # Load or create context
        if self.config.get("context_file", None):
            log.info("Loading context")
            # Load context from file
            context_data = self._zap_api.context.import_context(self.config.get("context_file"))
            self._zap_context_name = self._zap_api.context.context_list[int(context_data) - 1]
            self._zap_context = context_data
        else:
            log.info("Preparing context")
            # Create new context
            self._zap_context_name = "dusty"
            self._zap_context = self._zap_api.context.new_context(self._zap_context_name)
            # Add hostname includsion for newly created context
            self._zap_api.context.include_in_context(
                self._zap_context_name,
                f".*{re.escape(url.parse_url(self.config.get('target')).hostname)}.*"
            )
        # Setup context inclusions and exclusions
        for include_regex in self.config.get("include", list()):
            self._zap_api.context.include_in_context(self._zap_context_name, include_regex)
        # - exclude from context
        if self.config.get("exclude_from_context", True):
            for exclude_regex in self.config.get("exclude", list()):
                self._zap_api.context.exclude_from_context(self._zap_context_name, exclude_regex)
            additional_excludes = self.config.get("exclude_from_context", list())
            if isinstance(additional_excludes, list):
                for exclude_regex in additional_excludes:
                    self._zap_api.context.exclude_from_context(
                        self._zap_context_name, exclude_regex
                    )
        # - exclude from spider
        if self.config.get("exclude_from_spider", True):
            for exclude_regex in self.config.get("exclude", list()):
                self._zap_api.spider.exclude_from_scan(exclude_regex)
            additional_excludes = self.config.get("exclude_from_spider", list())
            if isinstance(additional_excludes, list):
                for exclude_regex in additional_excludes:
                    self._zap_api.spider.exclude_from_scan(exclude_regex)
        # - exclude from ascan
        if self.config.get("exclude_from_ascan", True):
            for exclude_regex in self.config.get("exclude", list()):
                self._zap_api.ascan.exclude_from_scan(exclude_regex)
            additional_excludes = self.config.get("exclude_from_ascan", list())
            if isinstance(additional_excludes, list):
                for exclude_regex in additional_excludes:
                    self._zap_api.ascan.exclude_from_scan(exclude_regex)
        # - exclude from proxy
        if self.config.get("exclude_from_proxy", True):
            for exclude_regex in self.config.get("exclude", list()):
                self._zap_api.core.exclude_from_proxy(exclude_regex)
            additional_excludes = self.config.get("exclude_from_proxy", list())
            if isinstance(additional_excludes, list):
                for exclude_regex in additional_excludes:
                    self._zap_api.core.exclude_from_proxy(exclude_regex)
        # Auth script
        if self.config.get("auth_script", None):
            # Load our authentication script
            self._zap_api.script.load(
                scriptname="zap-selenium-login.js",
                scripttype="authentication",
                scriptengine="Oracle Nashorn",
                filename=pkg_resources.resource_filename(
                    "dusty",
                    f"{'/'.join(__name__.split('.')[1:-1])}/data/zap-selenium-login.js"
                ),
                scriptdescription="Login via selenium script"
            )
            # Enable use of loaded script with supplied selenium-like script
            self._zap_api.authentication.set_authentication_method(
                self._zap_context,
                "scriptBasedAuthentication",
                urllib.parse.urlencode({
                    "scriptName": "zap-selenium-login.js",
                    "Target": self.config.get("target"),
                    "Script": base64.b64encode(
                        json.dumps(
                            self.config.get("auth_script")
                        ).encode("utf-8")
                    ).decode("utf-8")
                })
            )
            # Add user to context
            self._zap_user = self._zap_api.users.new_user(self._zap_context, "dusty_user")
            self._zap_api.users.set_authentication_credentials(
                self._zap_context,
                self._zap_user,
                urllib.parse.urlencode({
                    "Username": self.config.get("auth_login", ""),
                    "Password": self.config.get("auth_password", ""),
                    "type": "UsernamePasswordAuthenticationCredentials"
                })
            )
            # Enable added user
            self._zap_api.users.set_user_enabled(self._zap_context, self._zap_user, True)
            # Setup auth indicators
            if self.config.get("logged_in_indicator", None):
                self._zap_api.authentication.set_logged_in_indicator(
                    self._zap_context, self.config.get("logged_in_indicator")
                )
            if self.config.get("logged_out_indicator", None):
                self._zap_api.authentication.set_logged_out_indicator(
                    self._zap_context, self.config.get("logged_out_indicator")
                )

    def _setup_scan_policy(self):
        self._scan_policy_name = "Default Policy"
        # Use user-provided policy (if any)
        if self.config.get("scan_policy_data", None) or self.config.get("scan_policy_from", None):
            log.info("Using user-provided scan policy")
            # Write to temp file if needed
            if self.config.get("scan_policy_data", None):
                policy_file_fd, policy_file = tempfile.mkstemp()
                os.close(policy_file_fd)
                with open(policy_file, "w") as policy:
                    log.debug("Scan policy data: '%s'", self.config.get("scan_policy_data"))
                    policy.write(self.config.get("scan_policy_data"))
            else:
                policy_file = self.config.get("scan_policy_from")
            # Load policy into ZAP
            default_policies = self._zap_api.ascan.scan_policy_names
            log.info("Importing scan policy from %s", policy_file)
            self._zap_api.ascan.import_scan_policy(policy_file)
            current_policies = self._zap_api.ascan.scan_policy_names
            log.debug("Policies after load: %s", current_policies)
            # Remove temporary file
            if self.config.get("scan_policy_data", None):
                os.remove(policy_file)
            # Set name
            loaded_policy_names = list(set(current_policies) - set(default_policies))
            if loaded_policy_names:
                self._scan_policy_name = loaded_policy_names[0]
                log.info("Scan policy set to '%s'", self._scan_policy_name)
            return
        # Setup 'simple' scan policy
        self._scan_policies = [
            item.strip() for item in self.config.get("scan_types", "all").split(",")
        ]
        # Disable globally blacklisted rules
        for item in constants.ZAP_BLACKLISTED_RULES:
            self._zap_api.ascan.set_scanner_alert_threshold(
                id=item,
                alertthreshold="OFF",
                scanpolicyname=self._scan_policy_name
            )
            self._zap_api.pscan.set_scanner_alert_threshold(
                id=item,
                alertthreshold="OFF"
            )
        if "all" not in self._scan_policies:
            # Disable all scanners first
            for item in self._zap_api.ascan.scanners(self._scan_policy_name):
                self._zap_api.ascan.set_scanner_alert_threshold(
                    id=item["id"],
                    alertthreshold="OFF",
                    scanpolicyname=self._scan_policy_name
                )
            # Enable scanners from suite
            for policy in self._scan_policies:
                for item in constants.ZAP_SCAN_POCILICES.get(policy, []):
                    self._zap_api.ascan.set_scanner_alert_threshold(
                        id=item,
                        alertthreshold="DEFAULT",
                        scanpolicyname=self._scan_policy_name)

    def _spider(self):
        log.info("Spidering target: %s", self.config.get("target"))
        if self.config.get("auth_script", None):
            scan_id = self._zap_api.spider.scan_as_user(
                self._zap_context, self._zap_user, self.config.get("target"),
                recurse=True, subtreeonly=True
            )
        else:
            scan_id = self._zap_api.spider.scan(self.config.get("target"))
        #
        try:
            int(scan_id)
        except:  # pylint: disable=W0702
            log.warning("ZAP failed to return scan ID (scan_id=%s). Please check that target URL is accessible from Carrier DAST container", scan_id)  # pylint: disable=C0301
            return
        #
        status.wait_for_completion(
            lambda: int(self._zap_api.spider.status(scan_id)) < 100,
            lambda: int(self._zap_api.spider.status(scan_id)),
            "Spidering progress: %d%%"
        )

    def _ajax_spider(self):
        log.info("Ajax spidering target: %s", self.config.get("target"))
        if self.config.get("auth_script", None):
            self._zap_api.ajaxSpider.scan_as_user(
                self._zap_context_name, "dusty_user", self.config.get("target"), subtreeonly=True
            )
        else:
            self._zap_api.ajaxSpider.scan(self.config.get("target"))
        status.wait_for_completion(
            lambda: self._zap_api.ajaxSpider.status == 'running',
            lambda: int(self._zap_api.ajaxSpider.number_of_results),
            "Ajax spider found: %d URLs"
        )

    def _active_scan(self):
        log.info("Active scan against target %s", self.config.get("target"))
        if self.config.get("auth_script", None):
            scan_id = self._zap_api.ascan.scan_as_user(
                self.config.get("target"), self._zap_context, self._zap_user, recurse=True,
                scanpolicyname=self._scan_policy_name
            )
        else:
            scan_id = self._zap_api.ascan.scan(
                self.config.get("target"),
                scanpolicyname=self._scan_policy_name
            )
        #
        try:
            int(scan_id)
        except:  # pylint: disable=W0702
            log.warning("ZAP failed to return scan ID (scan_id=%s). Please check that target URL is accessible from Carrier DAST container", scan_id)  # pylint: disable=C0301
            return
        #
        status.wait_for_completion(
            lambda: int(self._zap_api.ascan.status(scan_id)) < 100,
            lambda: int(self._zap_api.ascan.status(scan_id)),
            "Active scan progress: %d%%"
        )

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(
            len(data_obj), "scan_types", "all",
            comment="ZAP scan type, supported any combination of: 'all', 'xss', 'sqli'"
        )
        data_obj.insert(len(data_obj), "target", "http://app:8080", comment="scan target")
        data_obj.insert(
            len(data_obj), "context_file", "/path/to/zap_context",
            comment="(optional) Path to ZAP context file"
        )
        data_obj.insert(
            len(data_obj), "include", ["http://app:8080/path.*"],
            comment="(optional) URLs regex to additionally include in scan"
        )
        data_obj.insert(
            len(data_obj), "exclude", ["http://app:8080/logout.*"],
            comment="(optional) URLs regex to exclude from scan"
        )
        data_obj.insert(
            len(data_obj), "exclude_from_context", True,
            comment="(optional) True/False to add data from exclude option." \
                "Or URLs regex list to exclude from context"
        )
        data_obj.insert(
            len(data_obj), "exclude_from_spider", True,
            comment="(optional) True/False to add data from exclude option." \
                "Or URLs regex list to exclude from spider"
        )
        data_obj.insert(
            len(data_obj), "exclude_from_ascan", True,
            comment="(optional) True/False to add data from exclude option." \
                "Or URLs regex list to exclude from active scan"
        )
        data_obj.insert(
            len(data_obj), "exclude_from_proxy", True,
            comment="(optional) True/False to add data from exclude option." \
                "Or URLs regex list to exclude from proxy"
        )
        data_obj.insert(
            len(data_obj), "logged_in_indicator", "Logout",
            comment="(optional) Response regex that is always present for authenticated user"
        )
        data_obj.insert(
            len(data_obj), "logged_out_indicator", "Register a new account",
            comment="(optional) Response regex that is present for unauthenticated user"
        )
        data_obj.insert(
            len(data_obj), "auth_login", "user",
            comment="(optional) User login for authenticated scan"
        )
        data_obj.insert(
            len(data_obj), "auth_password", "P@ssw0rd",
            comment="(optional) User password for authenticated scan"
        )
        data_obj.insert(
            len(data_obj), "auth_script", CommentedSeq(),
            comment="(optional) Selenium-like script for authenticated scan"
        )
        script_obj = data_obj["auth_script"]
        for command in [
                {"command": "open", "target": "%Target%/login", "value": ""},
                {"command": "waitForElementPresent", "target": "id=login_login", "value": ""},
                {"command": "waitForElementPresent", "target": "id=login_password", "value": ""},
                {"command": "waitForElementPresent", "target": "id=login_0", "value": ""},
                {"command": "type", "target": "id=login_login", "value": "%Username%"},
                {"command": "type", "target": "id=login_password", "value": "%Password%"},
                {"command": "clickAndWait", "target": "id=login_0", "value": ""}
        ]:
            command_obj = CommentedMap()
            command_obj.fa.set_flow_style()
            for key in ["command", "target", "value"]:
                command_obj.insert(len(command_obj), key, command[key])
            script_obj.append(command_obj)
        data_obj.insert(
            len(data_obj), "bind_all_interfaces", True,
            comment="(optional) Bind ZAP to all interfaces or only to localhost"
        )
        data_obj.insert(
            len(data_obj), "daemon_debug", False,
            comment="(optional) Send ZAP daemon output to stdout"
        )
        data_obj.insert(
            len(data_obj), "java_options", "-Xmx1g",
            comment="(optional) Java options for ZAP daemon"
        )
        data_obj.insert(
            len(data_obj), "split_by_endpoint", False,
            comment="(optional) Create separate findings for every endpoint"
        )
        data_obj.insert(
            len(data_obj), "passive_scan_wait_threshold", 0,
            comment="(optional) Wait until N items left in passive scan queue"
        )
        data_obj.insert(
            len(data_obj), "passive_scan_wait_limit", 600,
            comment="(optional) Time limit (in seconds) for passive scan"
        )
        data_obj.insert(
            len(data_obj), "external_zap_daemon", "http://192.168.0.2:8091",
            comment="(optional) Do not start internal ZAP daemon, use external one"
        )
        data_obj.insert(
            len(data_obj), "external_zap_api_key", "dusty",
            comment="(optional) API key for external ZAP daemon"
        )
        data_obj.insert(
            len(data_obj), "save_intermediates_to", "/data/intermediates/dast",
            comment="(optional) Save scan intermediates (raw results, logs, ...)"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["target"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def get_name():
        """ Module name """
        return "OWASP ZAP"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "OWASP Zed Attack Proxy (ZAP)"
