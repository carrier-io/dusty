#   Copyright 2018 getcarrier.io
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

from dusty.data_model.canonical_model import DefaultModel as Finding
from json import load


class SslyzeJSONParser(object):
    def __init__(self, file, test):
        with open(file, "rb") as f:
            data = load(f)
        self.items = []
        severity = 'Medium'
        tool = 'sslyze'
        dynamic_finding = True
        scanner_confidence = 'certain'
        for target in data['accepted_targets']:
            chain_info = ""
            for each in target['commands_results']["certinfo"]['certificate_chain']:
                chain_info += f'{each["subject"]}\n'
            certificate_validation = []
            for validation_result in target['commands_results']['certinfo']['path_validation_result_list']:
                if validation_result['verify_string'] != 'ok':
                    certificate_validation.append(f"Certificate chain is not trusted by "
                                                  f"{validation_result['trust_store']['name']} "
                                                  f"trust_store version {validation_result['trust_store']['version']}")
            if certificate_validation:
                descr = "\n".join(certificate_validation)
                self.items.append(Finding(title="Certificate is not trusted",
                                          severity=severity,
                                          description=f'Certificate chain: {chain_info}\n {descr}',
                                          tool=tool,
                                          endpoint=[chain_info],
                                          dynamic_finding=dynamic_finding,
                                          scanner_confidence=scanner_confidence))
            if target['commands_results']['heartbleed']['is_vulnerable_to_heartbleed']:
                self.items.append(Finding(title="Certificate is vulnerable to Heardbleed",
                                          severity=severity,
                                          description=f'Certificate chain: {chain_info}\n is vulnerable to heartbleed',
                                          tool=tool,
                                          endpoint=[chain_info],
                                          dynamic_finding=dynamic_finding,
                                          scanner_confidence=scanner_confidence))
            if 'NOT_VULNERABLE' not in target['commands_results']['robot']['robot_result_enum']:
                self.items.append(Finding(title="Certificate is vulnerable to Robot",
                                          severity=severity,
                                          description=f'Certificate chain: {chain_info}\n '
                                                      f'is vulnerable to robot with '
                                                      f'{target["commands_results"]["robot"]["robot_result_enum"]}',
                                          tool=tool,
                                          endpoint=[chain_info],
                                          dynamic_finding=dynamic_finding,
                                          scanner_confidence=scanner_confidence))
            if target['commands_results']['openssl_ccs']['is_vulnerable_to_ccs_injection']:
                self.items.append(Finding(title="Certificate is vulnerable to CCS Injection",
                                          severity=severity,
                                          description=f'Certificate chain: {chain_info}\n '
                                                      f'is vulnerable to CCS Injection',
                                          tool=tool,
                                          endpoint=[chain_info],
                                          dynamic_finding=dynamic_finding,
                                          scanner_confidence=scanner_confidence))


