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
    Scanner: Nmap
"""

import os
import re
import shlex
import shutil
import tempfile
import subprocess

from dusty.tools import log, url
from dusty.models.module import DependentModuleModel
from dusty.models.scanner import ScannerModel

from .parser import parse_findings


class Scanner(DependentModuleModel, ScannerModel):
    """ Scanner class """

    def __init__(self, context):
        """ Initialize scanner instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["scanners"][__name__.split(".")[-3]][__name__.split(".")[-2]]

    def execute(self):
        """ Run the scanner """
        # Discover open ports
        include_ports = list()
        if self.config.get("include_ports", "0-65535"):
            include_ports.append(f'-p{self.config.get("include_ports", "0-65535")}')
        exclude_ports = list()
        if self.config.get("exclude_ports", None):
            exclude_ports.append("--exclude-ports")
            exclude_ports.append(f'{self.config.get("exclude_ports")}')
        target_url = url.parse_url(self.config.get("target"))
        task = subprocess.run(["nmap", "-PN"] + include_ports + exclude_ports + [
            "--min-rate", "1000", "--max-retries", "0", "--max-rtt-timeout", "200ms",
            target_url.hostname
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log.log_subprocess_result(task)
        # Use discovered ports
        ports = list()
        tcp_ports = ""
        udp_ports = ""
        for each in re.findall(r'([0-9]*/[tcp|udp])', str(task.stdout)):
            if "/t" in each:
                tcp_ports += f'{each.replace("/t", "")},'
            elif "/u" in each:
                udp_ports += f'{each.replace("/u", "")},'
        if tcp_ports:
            ports.append(f"-pT:{tcp_ports[:-1]}")
        if udp_ports:
            ports.append(f"-pU:{udp_ports[:-1]}")
        if not ports:
            log.warning("No open ports found. Exiting")
            return
        # Make temporary files
        output_file_fd, output_file = tempfile.mkstemp()
        log.debug("Output file: %s", output_file)
        os.close(output_file_fd)
        # Scan target
        nmap_parameters = shlex.split(self.config.get("nmap_parameters", "-v -sVA"))
        nse_scripts = self.config.get(
            "nse_scripts",
            "ssl-date,http-mobileversion-checker,http-robots.txt,http-title,http-waf-detect,"
            "http-chrono,http-headers,http-comments-displayer,http-date"
        )
        task = subprocess.run(["nmap"] + nmap_parameters + ports + [
            "--min-rate", "1000", "--max-retries", "0", f'--script={nse_scripts}',
            target_url.hostname, "-oX", output_file
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log.log_subprocess_result(task)
        # Parse findings
        parse_findings(output_file, self)
        # Save intermediates
        self.save_intermediates(output_file, task)
        # Remove temporary files
        os.remove(output_file)

    def save_intermediates(self, output_file, task):
        """ Save scanner intermediates """
        if self.config.get("save_intermediates_to", None):
            log.info("Saving intermediates")
            base = os.path.join(self.config.get("save_intermediates_to"), __name__.split(".")[-2])
            try:
                # Make directory for artifacts
                os.makedirs(base, mode=0o755, exist_ok=True)
                # Save report
                shutil.copyfile(
                    output_file,
                    os.path.join(base, "report.xml")
                )
                # Save output
                with open(os.path.join(base, "output.stdout"), "w") as output:
                    output.write(task.stdout.decode("utf-8", errors="ignore"))
                with open(os.path.join(base, "output.stderr"), "w") as output:
                    output.write(task.stderr.decode("utf-8", errors="ignore"))
            except:
                log.exception("Failed to save intermediates")

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(len(data_obj), "target", "http://app:4502", comment="scan target")
        data_obj.insert(
            len(data_obj), "include_ports", "0-65535",
            comment="(optional) Ports to scan"
        )
        data_obj.insert(
            len(data_obj), "exclude_ports", "1,4-40,4444",
            comment="(optional) Ports to exclude"
        )
        data_obj.insert(
            len(data_obj), "include_unfiltered", False,
            comment="(optional) Include 'unfiltered' ports in report"
        )
        data_obj.insert(
            len(data_obj), "nmap_parameters", "-v -sVA",
            comment="(optional) Additional scanner parameters"
        )
        data_obj.insert(
            len(data_obj), "nse_scripts", "ssl-date,http-mobileversion-checker",
            comment="(optional) NSE scripts to use"
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
        return "Nmap"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "Nmap Security Scanner"
