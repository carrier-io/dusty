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
    try:
        # Process each scanned target result
        for target in data["server_scan_results"]:
            # Heartbleed
            if target["scan_result"]["heartbleed"]["result"]["is_vulnerable_to_heartbleed"]:
                finding = DastFinding(
                    title="SSL: Server is vulnerable to HeartBleed",
                    description=markdown.markdown_escape(
                        f"Server is vulnerable to heartbleed"
                    )
                )
                finding.set_meta("tool", scanner.get_name())
                finding.set_meta("severity", severity)
                scanner.findings.append(finding)
            # CCS Injection
            if target[
                    "scan_result"
            ]["openssl_ccs_injection"]["result"]["is_vulnerable_to_ccs_injection"]:
                finding = DastFinding(
                    title="SSL: Server is vulnerable to CCS Injection",
                    description=markdown.markdown_escape(
                        f"Server is vulnerable to CCS Injection"
                    )
                )
                finding.set_meta("tool", scanner.get_name())
                finding.set_meta("severity", severity)
                scanner.findings.append(finding)
            # Robot
            if "NOT_VULNERABLE" not in target["scan_result"]["robot"]["result"]["robot_result"]:
                finding = DastFinding(
                    title="SSL: Server is vulnerable to Robot",
                    description=markdown.markdown_escape(
                        f"SSL server is vulnerable to robot with "
                        f'{target["scan_result"]["robot"]["robot_result"]}'
                    )
                )
                finding.set_meta("tool", scanner.get_name())
                finding.set_meta("severity", severity)
                scanner.findings.append(finding)
            # Client renegotiation DoS
            if target[
                    "scan_result"
            ]["session_renegotiation"]["result"]["is_vulnerable_to_client_renegotiation_dos"]:
                finding = DastFinding(
                    title="SSL: Server is vulnerable to Client renegotiation DoS",
                    description=markdown.markdown_escape(
                        f"Server is vulnerable to Client renegotiation DoS"
                    )
                )
                finding.set_meta("tool", scanner.get_name())
                finding.set_meta("severity", severity)
                scanner.findings.append(finding)
            # Certificate validation
            for deployment in target[
                    "scan_result"
            ]["certificate_info"]["result"]["certificate_deployments"]:
                # Collect target chain info
                chain_info = ""
                for each in reversed(deployment["received_certificate_chain"]):
                    chain_info += f'{each["subject"]["rfc4514_string"]}\n\n'
                # Collect certificate chain validation info
                certificate_validation = []
                for validation_result in deployment["path_validation_results"]:
                    if validation_result["verified_certificate_chain"] is None:
                        certificate_validation.append(
                            f"- Is not trusted by "
                            f"{validation_result['trust_store']['name']} "
                            f"({validation_result['trust_store']['version']})"
                        )
                # Create finding object
                if certificate_validation:
                    descr = "\n\n".join(certificate_validation)
                    finding = DastFinding(
                        title="SSL: Certificate is not trusted",
                        description=markdown.markdown_escape(
                            f"Certificate chain: \n\n{chain_info}\n {descr}"
                        )
                    )
                    finding.set_meta("tool", scanner.get_name())
                    finding.set_meta("severity", severity)
                    scanner.findings.append(finding)
    except:  # pylint: disable=W0702
        log.exception("Failed to parse results")
