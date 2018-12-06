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

import hashlib
import markdown2
from junit_xml import TestCase


class Endpoint(object):
    def __init__(self, protocol=None, host=None, fqdn=None, port=None, path=None, query=None, fragment=None, **kwargs):

        self.protocol = protocol  # The communication protocol such as 'http', 'ftp', etc.
        self.host = host    # The host name or IP address, you can also include the port number.
                            # For example '127.0.0.1', '127.0.0.1:8080', 'localhost', 'yourdomain.com'.
        self.fqdn = fqdn    # Fully qualified domain name (FQDN) is the complete domain name
        self.port = port    # The network port associated with the endpoint.
        self.path = path    # The location of the resource, it should start with a '/'.
                            # For example/endpoint/420/edit"
        self.query = query  # "The query string, the question mark should be omitted.
                            # For example 'group=4&team=8'"
        self.fragment = fragment  # "The fragment identifier which follows the hash mark. The hash mark should
                                  # be omitted. For example 'section-13', 'paragraph-2'."

    def __str__(self):
        str_repr = ""
        if self.protocol:
            str_repr = f'{self.protocol}://'
        if self.host:
            str_repr += self.fqdn if self.fqdn else self.host
        if self.port:
            str_repr += f":{self.port}"
        if self.path:
            str_repr += f"{self.path}"
        if self.query:
            str_repr += f"?{self.query}"
        return str_repr


class DefaultModel(object):
    def __init__(self, title, severity, description, tool, endpoints=None,
                 scanner_confidence=None, static_finding=None, dynamic_finding=None,
                 impact=None, mitigation=None, date=None, cwe=None, url=None,
                 steps_to_reproduce=None, severity_justification=None,
                 references=None, images=None, line_number=None,
                 sourcefilepath=None, sourcefile=None, param=None,
                 payload=None, line=None, file_path=None,
                 **kwags):
        endpoints = [] if not endpoints else endpoints
        self.finding = {
            "title": title,
            "date": date,
            "description": description.replace("\n", "\n\n"),
            "severity": severity,
            "confidence": scanner_confidence,
            "tool": tool,
            "static_finding": static_finding,
            "dynamic_finding": dynamic_finding,
            "steps_to_reproduce": steps_to_reproduce,
            "references": references,
            "impact": impact,
            "mitigation": mitigation,
            "severity_justification": severity_justification,
            "static_finding_details": {
                "file_name": file_path if file_path else f"{sourcefilepath}.{sourcefile}",
                "line_number": line if line else line_number,
                "cwe": cwe,
                "url": url
            },
            "dynamic_finding_details": {
                "payload": payload if payload else param,
                "cwe": cwe,
                "url": url,
                "endpoints": endpoints
            },
            "error_string": None,
            "error_hash": None
        }
        self.unsaved_endpoints = []
        self.images = [] if not images else images
        self.endpoints = []
        self.scan_type = ""

    def get_numerical_severity(self) -> int:
        return 0

    def finding_error_string(self) -> str:
        endpoint_str = ""
        for e in self.endpoints:
            endpoint_str += str(e)
        return f'{self.finding["title"]}_' \
               f'{self.finding["static_finding_details"]["cwe"]}_' \
               f'{self.finding["static_finding_details"]["line_number"]}_' \
               f'{self.finding["static_finding_details"]["file_name"]}_' \
               f'{endpoint_str}'

    def get_hash_code(self) -> str:
        hash_string = self.finding_error_string().strip()
        #print(hash_string)
        return hashlib.sha256(hash_string.encode('utf-8')).hexdigest()

    def __str__(self):
        finding = f'\n### Title: {self.finding["title"]}\n\n' \
                  f'### Description:\n {self.finding["description"]}\n\n' \
                  f'**Tool**: {self.finding["tool"]}\n\n' \
                  f'**Severity**: {self.finding["severity"]}\n\n'
        for each in self.finding:
            if each in ["error_string", "error_hash", "images", "title", "description", "tool", "severity",
                        "dynamic_finding", "static_finding", "static_finding_details"]:
                continue
            else:
                if self.finding[each] and 'N/A' not in self.finding[each] and not isinstance(self.finding[each], dict):
                    finding += f"**{each}**: {self.finding[each]}\n"

        if self.finding['static_finding_details']['file_name'] and \
                self.finding['static_finding_details']['line_number']:
            self.scan_type = 'SAST'
            finding += f'**Please review**: ' \
                       f'{self.finding["static_finding_details"]["file_name"]}: ' \
                       f'{self.finding["static_finding_details"]["line_number"]}\n\n'
        endpoints = set(self.finding['dynamic_finding_details']['endpoints'] + self.unsaved_endpoints + self.endpoints)
        if endpoints:
            self.scan_type = "DAST"
            finding += "### Endpoints:\n"
            for endpoint in endpoints:
                finding += f'{str(endpoint)}\n\n'
        if self.finding['dynamic_finding_details']['payload']:
            finding += f"**Payload:** {self.finding[each]['payload']}\n\n"
        return finding

    def rp_item(self, rp_data_writer):
        item_details = self.__str__()
        tags = [f'Tool: {self.finding["tool"]}', f'TestType: {self.scan_type}', f'Severity: {self.finding["severity"]}']
        if self.finding['confidence']:
            tags.append(f'Confidence: {self.finding["confidence"]}')
        rp_data_writer.start_test_item(self.finding["title"],
                                       description=self.finding['description'],
                                       tags=tags)
        if self.images:
            for attachment in self.images:
                rp_data_writer.test_item_message(attachment['name'], 'INFO', attachment)
        rp_data_writer.test_item_message('!!!MARKDOWN_MODE!!! %s ' % item_details, 'INFO')
        rp_data_writer.test_item_message(self.get_hash_code(), 'ERROR')
        rp_data_writer.finish_test_item()

    def html_item(self):
        return markdown2.markdown(self.__str__())

    def junit_item(self):
        tc = TestCase(self.finding['title'], classname=self.finding["tool"])
        message = self.__str__()
        tc.add_error_info(message=message, error_type=self.finding['severity'])
        return tc

    def influx_item(self):
        pass

    def dd_item(self):
        pass