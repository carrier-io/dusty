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
    Qualys WAS XML parser
"""

import html
import base64

from defusedxml.cElementTree import fromstring

from dusty.tools import log, url, markdown
from dusty.models.finding import DastFinding

from . import constants


def parse_findings(data, scanner):
    """ Parse findings """
    log.debug("Parsing findings")
    obj = fromstring(data)
    qids = obj.xpath("/WAS_WEBAPP_REPORT/GLOSSARY/QID_LIST/QID")
    disabled_titles = constants.QUALYS_DISABLED_TITLES
    for qid in qids:
        qid_title = qid.findtext("TITLE")
        if qid_title not in disabled_titles:
            _qid = qid.findtext("QID")
            qid_solution = qid.findtext("SOLUTION")
            qid_description = qid.findtext("DESCRIPTION")
            qid_impact = qid.findtext("IMPACT")
            qid_category = qid.findtext("CATEGORY")
            qid_severity = "Info"
            owasp = qid.findtext("OWASP") if qid.findtext("OWASP") else ""
            wasc = qid.findtext("WASC") if qid.findtext("WASC") else ""
            cwe = qid.findtext("CWE") if qid.findtext("CWE") else ""
            cvss_base = qid.findtext("CVSS_BASE") if qid.findtext("CVSS_BASE") else ""
            if qid.xpath("SEVERITY"):
                qid_severity = constants.QUALYS_SEVERITIES[int(qid.findtext("SEVERITY"))]
            references = []
            entrypoints = []
            if "Information Gathered" in qid_category:
                qid_severity = "Info"
                records = obj.xpath(
                    f'//INFORMATION_GATHERED_LIST/INFORMATION_GATHERED/QID[text()="{_qid}"]/..'
                )
                for record in records:
                    try:
                        references.append(html.escape(
                            base64.b64decode(
                                record.findtext("DATA")
                            ).decode("utf-8", errors="ignore")
                        ))
                    except:  # pylint: disable=W0702
                        log.exception("Failed to add information reference. Skipping")
            else:
                records = obj.xpath(f'//VULNERABILITY_LIST/VULNERABILITY/QID[text()="{_qid}"]/..')
                for record in records:
                    record_url = record.findtext('URL')
                    access_pass = [a.text for a in records[0].xpath('ACCESS_PATH/URL')]
                    method = record.findtext('PAYLOADS/PAYLOAD/REQUEST/METHOD')
                    if not method:
                        log.error("Bad record: %s", str(record))
                        method = ""
                    request = record.findtext('PAYLOADS/PAYLOAD/REQUEST/URL')
                    request = html.escape(request)
                    response = record.findtext('PAYLOADS/PAYLOAD/RESPONSE/CONTENTS')
                    response = html.escape(
                        base64.b64decode(response).decode("utf-8", errors="ignore")
                    )
                    entrypoints.append(record_url)
                    entrypoints.extend(access_pass)
                    references.append(f"{method.upper()}: {request}\n\nResponse: {response}\n\n")
            for reference in references:
                description = f"{markdown.html_to_text(qid_description)}\n\n"
                if qid_impact:
                    description += f"**Impact:**\n {markdown.html_to_text(qid_impact)}\n\n"
                if qid_solution:
                    description += f"**Mitigation:**\n {markdown.html_to_text(qid_solution)}\n\n"
                if reference:
                    description += f"**References:**\n {markdown.markdown_escape(reference)}\n\n"
                if cwe:
                    description += f"**CWE:** {markdown.markdown_escape(cwe)}\n\n"
                if owasp:
                    description += f"**OWASP:** {markdown.markdown_escape(owasp)}\n\n"
                if wasc:
                    description += f"**WASC:** {markdown.markdown_escape(wasc)}\n\n"
                if cvss_base:
                    description += f"**CVSS_BASE:** {markdown.markdown_escape(cvss_base)}\n\n"
                # Make finding object
                finding = DastFinding(
                    title=f"{qid_title} - {qid_category}",
                    description=description
                )
                finding.set_meta("tool", scanner.get_name())
                finding.set_meta("severity", qid_severity)
                # Endpoints (for backwards compatibility)
                endpoints = list()
                for item in entrypoints:
                    endpoint = url.parse_url(item)
                    if endpoint in endpoints:
                        continue
                    endpoints.append(endpoint)
                finding.set_meta("endpoints", endpoints)
                log.debug(f"Endpoints: {finding.get_meta('endpoints')}")
                # Done
                scanner.findings.append(finding)
