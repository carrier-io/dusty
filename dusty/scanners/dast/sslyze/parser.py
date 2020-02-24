#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,W1401,E0401,R0914,R0915,R0912

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
    SSLyze JSON parser
"""

import json

from dusty.tools import log, markdown
from dusty.models.finding import DastFinding


def parse_findings(output_file, scanner):
    """ Parse findings (code from dusty 1.0) """
    log.debug("Parsing findings")
    # Load JSON
    with open(output_file, "rb") as json_file:
        data = json.load(json_file)
    # SSLyze report has no severity. Set all to Medium
    severity = "Medium"
    # Walk results
    for target in data["accepted_targets"]:
        chain_info = ""
        for each in target["commands_results"]["certinfo"]["certificate_chain"]:
            chain_info += f'{each["subject"]}\n'
        certificate_validation = []
        for validation_result in \
                target["commands_results"]["certinfo"]["path_validation_result_list"]:
            if validation_result["verify_string"] != "ok":
                certificate_validation.append(
                    f"Certificate chain is not trusted by "
                    f"{validation_result['trust_store']['name']} "
                    f"trust_store version {validation_result['trust_store']['version']}"
                )
        # Create finding objects
        if certificate_validation:
            descr = "\n".join(certificate_validation)
            finding = DastFinding(
                title="Certificate is not trusted",
                description=markdown.markdown_escape(
                    f"Certificate chain: {chain_info}\n {descr}"
                )
            )
            finding.set_meta("tool", scanner.get_name())
            finding.set_meta("severity", severity)
            scanner.findings.append(finding)
        if target["commands_results"]["heartbleed"]["is_vulnerable_to_heartbleed"]:
            finding = DastFinding(
                title="Certificate is vulnerable to Heardbleed",
                description=markdown.markdown_escape(
                    f"Certificate chain: {chain_info}\n is vulnerable to heartbleed"
                )
            )
            finding.set_meta("tool", scanner.get_name())
            finding.set_meta("severity", severity)
            scanner.findings.append(finding)
        if "NOT_VULNERABLE" not in target["commands_results"]["robot"]["robot_result_enum"]:
            finding = DastFinding(
                title="Certificate is vulnerable to Robot",
                description=markdown.markdown_escape(
                    f"Certificate chain: {chain_info}\n "
                    f"is vulnerable to robot with "
                    f'{target["commands_results"]["robot"]["robot_result_enum"]}'
                )
            )
            finding.set_meta("tool", scanner.get_name())
            finding.set_meta("severity", severity)
            scanner.findings.append(finding)
        if target["commands_results"]["openssl_ccs"]["is_vulnerable_to_ccs_injection"]:
            finding = DastFinding(
                title="Certificate is vulnerable to CCS Injection",
                description=markdown.markdown_escape(
                    f"Certificate chain: {chain_info}\n "
                    f"is vulnerable to CCS Injection"
                )
            )
            finding.set_meta("tool", scanner.get_name())
            finding.set_meta("severity", severity)
            scanner.findings.append(finding)
