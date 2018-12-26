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

import base64
import hashlib

import lxml.etree as le
from urllib.parse import urlparse
from dusty.data_model.canonical_model import DefaultModel as Finding


class W3AFXMLParser(object):
    def __init__(self, file, test=None):
        parser = le.XMLParser(resolve_entities=False, huge_tree=True)
        w3scan = le.parse(file, parser)
        root = w3scan.getroot()
        dupes = {}
        for vulnerability in root.findall("vulnerability"):
            name = vulnerability.attrib["name"]
            severity = vulnerability.attrib["severity"]
            description = "%s are:\n\n" % vulnerability.find("description").text.split("are:")[0]
            transactions = vulnerability.find("http-transactions")
            if transactions is not None:
                transactions = transactions.findall("http-transaction")
            for transaction in transactions:
                request = transaction.find("http-request")
                response = transaction.find("http-response")
                status = request.find("status").text.split(" ")
                response_code = response.find("status").text.split(" ")[1]
                http_method = status[0]
                request_url = status[1]
                data = ""
                for part in [request, response]:
                    headers = [f"{h.attrib['field']} -> {h.attrib['content']}" for h in part.find("headers").findall("header")]
                    headers = "\n".join(headers)
                    request_body = part.find("body")
                    if request_body.attrib['content-encoding'] == "base64":
                        if request_body.text:
                            request_body = base64.b64decode(request_body.text).decode("utf-8", errors="ignore")
                        else:
                            request_body = ""
                    else:
                        request_body = request_body.text if request_body.text else ""
                    if not data:
                        data = f"Request: {request_url} {http_method} {response_code} \n\n"
                    else:
                        data += "Response: \n"
                    data += f"Headers: {headers}\n\nBody:{request_body}\n\n"
                dupe_url = urlparse(request_url)
                # Creating dupe path ned to think on more intelligent implementation
                dupe_path = dupe_url.path[:dupe_url.path.index("%")] if "%" in dupe_url.path else dupe_url.path
                dupe_path = dupe_path[:dupe_path.index("+")] if "+" in dupe_path else dupe_path
                dupe_path = dupe_path[:dupe_path.index(".")] if "." in dupe_path else dupe_path
                dupe_path = dupe_path[:dupe_path.rindex("/")] if "/" in dupe_path else dupe_path
                dupe_url = f"{dupe_url.scheme}://{dupe_url.netloc}{dupe_path}"
                dupe_code = f"{str(response_code)[0]}xx"
                dupe_key = hashlib.md5(f"{name} {dupe_url} {http_method} {dupe_code}".encode('utf-8')).hexdigest()
                if dupe_key not in dupes:
                    dupes[dupe_key] = Finding(title=f"{name} {dupe_url} {dupe_code}", tool='W3AF', test=test,
                                              description=description, severity=severity,
                                              numerical_severity=Finding.get_numerical_severity(severity),
                                              references=data,
                                              dynamic_finding=True)
                elif data not in dupes[dupe_key].finding['references']:
                    dupes[dupe_key].finding['references'] += data
                if request_url not in dupes[dupe_key].unsaved_endpoints:
                    dupes[dupe_key].finding['description'] += f"- {request_url}\n\n"

                    dupes[dupe_key].unsaved_endpoints.append(request_url)
        self.items = dupes.values()
        print(len(self.items))




