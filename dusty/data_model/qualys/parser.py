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

import logging
import base64
import html
from lxml import etree
from dusty import constants as c
from dusty.data_model.canonical_model import DefaultModel as Finding

__author__ = "arozumenko"


class QualysWebAppParser(object):
    def __init__(self, file, test):
        self.items = []
        parser = etree.XMLParser(remove_blank_text=True, no_network=True, recover=True)
        d = etree.parse(file, parser)
        qids = d.xpath('/WAS_WEBAPP_REPORT/GLOSSARY/QID_LIST/QID')
        disabled_titles = ['Scan Diagnostics']
        for qid in qids:
            qid_title = qid.findtext('TITLE')
            if qid_title not in disabled_titles:
                _qid = qid.findtext('QID')
                qid_solution = qid.findtext('SOLUTION')
                qid_description = qid.findtext('DESCRIPTION')
                qid_impact = qid.findtext('IMPACT')
                qid_category = qid.findtext('CATEGORY')
                qid_severity = 'Info'
                owasp = qid.findtext('OWASP') if qid.findtext('OWASP') else ''
                wasc = qid.findtext('WASC') if qid.findtext('WASC') else ''
                cwe = qid.findtext('CWE') if qid.findtext('CWE') else ''
                cvss_base = qid.findtext('CVSS_BASE') if qid.findtext('CVSS_BASE') else ''
                if qid.xpath('SEVERITY'):
                    qid_severity = c.QUALYS_SEVERITIES[int(qid.findtext('SEVERITY'))]
                description = f'{qid_description}\n\n**OWASP**:{owasp}\n\n**WASC**:{wasc}\n\n**CVSS_BASE**:{cvss_base}\n\n'
                references = []
                entrypoints = []
                if 'Information Gathered' in qid_category:
                    qid_severity = 'Info'
                    records = d.xpath(f'//INFORMATION_GATHERED_LIST/INFORMATION_GATHERED/QID[text()="{_qid}"]/..')
                    for record in records:
                        references.append(html.escape(base64.b64decode(record.findtext('DATA')).decode("utf-8", errors="ignore")))
                else:
                    records = d.xpath(f'//VULNERABILITY_LIST/VULNERABILITY/QID[text()="{_qid}"]/..')
                    for record in records:
                        url = record.findtext('URL')
                        access_pass = [a.text for a in records[0].xpath('ACCESS_PATH/URL')]
                        method = record.findtext('PAYLOADS/PAYLOAD/REQUEST/METHOD')
                        if not method:
                            logging.error("Bad record: %s", str(record))
                            method = ""
                        request = record.findtext('PAYLOADS/PAYLOAD/REQUEST/URL')
                        response = record.findtext('PAYLOADS/PAYLOAD/RESPONSE/CONTENTS')
                        response = html.escape(base64.b64decode(response).decode("utf-8", errors="ignore"))
                        entrypoints.append(url)
                        entrypoints.extend(access_pass)
                        references.append(f"{method.upper()}: {request}\n\nResponse: {response}\n\n")
                for reference in references:
                    finding = Finding(title=f'{qid_title} - {qid_category}', tool="QualysWAS", cwe=cwe,
                                      description=description, test=test, severity=qid_severity,
                                      mitigation=qid_solution, references=reference,
                                      active=False, verified=False, false_p=False, duplicate=False,
                                      out_of_scope=False, mitigated=None, impact=qid_impact)
                    finding.unsaved_endpoints.extend(entrypoints)
                    self.items.append(finding)
