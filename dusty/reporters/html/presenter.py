#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,R0903,W0702

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
    HTML report presenter
"""

from dusty.models.finding import DastFinding, SastFinding
from dusty.constants import SEVERITIES
from dusty.tools import markdown, log

from .models import HTMLReportMeta, HTMLReportAlert, HTMLReportFinding, HTMLReportError


class HTMLPresenter:
    """ HTML presenter """

    def __init__(self, context, config):
        self.context = context
        self.config = config

    @staticmethod
    def _item_to_finding(item):
        if isinstance(item, DastFinding):
            return HTMLReportFinding(
                tool=item.get_meta("tool", ""),
                title=item.title,
                severity=item.get_meta("severity", SEVERITIES[-1]),
                description=markdown.markdown_to_html(item.description)
            )
        if isinstance(item, SastFinding):
            return HTMLReportFinding(
                tool=item.get_meta("tool", ""),
                title=item.title,
                severity=item.get_meta("severity", SEVERITIES[-1]),
                description=markdown.markdown_to_html("\n\n".join(item.description))
            )
        raise ValueError("Unsupported item type")

    def _group_findings_by_endpoints(self, items):
        result = list()
        try:
            endpoint_map = dict()
            ungrouped = list()
            # Prepare endpoint mapping
            for item in items:
                endpoints = item.get_meta("endpoints", None)
                if not endpoints:
                    ungrouped.append(item)
                    continue
                for endpoint in endpoints:
                    if endpoint not in endpoint_map:
                        endpoint_map[endpoint] = list()
                    endpoint_map[endpoint].append(item)
            # Make HTMLReportFinding instances
            for endpoint in sorted(endpoint_map.keys(), key=lambda item: item.raw):
                group = HTMLReportFinding(
                    tool="-",
                    title=f'Findings on {endpoint.raw}',
                    severity="-",
                    description=""
                )
                for finding in sorted(
                        endpoint_map[endpoint],
                        key=lambda item: (
                            SEVERITIES.index(item.get_meta("severity", SEVERITIES[-1])),
                            item.get_meta("tool", ""),
                            item.title
                        )
                ):
                    try:
                        group.findings.append(self._item_to_finding(finding))
                    except:
                        log.exception("Failed to create finding item")
                result.append(group)
            if ungrouped:
                group = HTMLReportFinding(
                    tool="-",
                    title="Findings with no endpoint",
                    severity="-",
                    description=""
                )
                for finding in sorted(
                        ungrouped,
                        key=lambda item: (
                            SEVERITIES.index(item.get_meta("severity", SEVERITIES[-1])),
                            item.get_meta("tool", ""),
                            item.title
                        )
                ):
                    try:
                        group.findings.append(self._item_to_finding(finding))
                    except:
                        log.exception("Failed to create finding item")
                result.append(group)
        except:
            log.exception("Error during findings grouping")
        # Done
        return result

    @property
    def project_name(self):
        """ Returns project name """
        return self.context.get_meta("project_name", "Unnamed Project")

    @property
    def project_meta(self):
        """ Returns project meta """
        result = list()
        result.append(HTMLReportMeta(
            name="Project name",
            value=self.context.get_meta("project_name", "Unnamed Project")
        ))
        if self.context.get_meta("project_description", None):
            result.append(HTMLReportMeta(
                name="Application name",
                value=self.context.get_meta("project_description")
            ))
        if self.context.get_meta("environment_name", None):
            result.append(HTMLReportMeta(
                name="Environment",
                value=self.context.get_meta("environment_name")
            ))
        if self.context.get_meta("testing_type", None):
            result.append(HTMLReportMeta(
                name="Testing type",
                value=self.context.get_meta("testing_type")
            ))
        if self.context.get_meta("dast_target", None):
            result.append(HTMLReportMeta(
                name="DAST target",
                value=self.context.get_meta("dast_target")
            ))
        if self.context.get_meta("sast_code", None):
            result.append(HTMLReportMeta(
                name="SAST code",
                value=self.context.get_meta("sast_code")
            ))
        if self.context.get_meta("scan_type", None):
            result.append(HTMLReportMeta(
                name="Scan type",
                value=self.context.get_meta("scan_type")
            ))
        if self.context.get_meta("build_id", None):
            result.append(HTMLReportMeta(
                name="Build ID",
                value=self.context.get_meta("build_id")
            ))
        if self.context.get_meta("dusty_version", None):
            result.append(HTMLReportMeta(
                name="Dusty version",
                value=self.context.get_meta("dusty_version")
            ))
        testing_time = self.context.performers["reporting"].get_module_meta(
            "time_meta", "testing_run_time", None
        )
        if testing_time:
            result.append(HTMLReportMeta(
                name="Testing time",
                value=f"{testing_time} second(s)"
            ))
        result.append(HTMLReportMeta(
            name="Total findings",
            value=str(len(self.project_findings))
        ))
        result.append(HTMLReportMeta(
            name="Total false positives",
            value=str(len(self.project_false_positive_findings))
        ))
        result.append(HTMLReportMeta(
            name="Total information findings",
            value=str(len(self.project_information_findings))
        ))
        result.append(HTMLReportMeta(
            name="Total excluded findings",
            value=str(len(self.project_excluded_findings))
        ))
        result.append(HTMLReportMeta(
            name="Total errors",
            value=str(len(self.project_errors))
        ))
        return result

    @property
    def project_alerts(self):
        """ Returns project alerts """
        result = list()
        if self.project_errors:
            result.append(HTMLReportAlert(
                type_="warning",
                text=f"Errors occurred during testing, result may be incomplete"
            ))
        if self.project_findings:
            result.append(HTMLReportAlert(
                type_="danger",
                text=f"Security testing FAILED, found {len(self.project_findings)} findings"
            ))
        else:
            result.append(HTMLReportAlert(
                type_="success",
                text=f"Security testing PASSED"
            ))
        return result

    @property
    def project_findings(self):
        """ Returns project findings """
        result = list()
        if self.config.get("group_by_endpoint", False):
            result.extend(self._group_findings_by_endpoints([
                item for item in self.context.findings \
                if not item.get_meta("information_finding", False) \
                and not item.get_meta("false_positive_finding", False) \
                and not item.get_meta("excluded_finding", False)
            ]))
        else:
            for item in self.context.findings:
                if item.get_meta("information_finding", False) or \
                        item.get_meta("false_positive_finding", False) or \
                        item.get_meta("excluded_finding", False):
                    continue
                try:
                    result.append(self._item_to_finding(item))
                except:
                    log.exception("Failed to create finding item")
            result.sort(key=lambda item: (SEVERITIES.index(item.severity), item.tool, item.title))
        return result

    @property
    def project_information_findings(self):
        """ Returns project information findings """
        result = list()
        if self.config.get("group_by_endpoint", False):
            result.extend(self._group_findings_by_endpoints([
                item for item in self.context.findings \
                if item.get_meta("information_finding", False) \
                and not item.get_meta("false_positive_finding", False) \
                and not item.get_meta("excluded_finding", False)
            ]))
        else:
            for item in self.context.findings:
                if item.get_meta("information_finding", False) and \
                        not item.get_meta("false_positive_finding", False) and \
                        not item.get_meta("excluded_finding", False):
                    try:
                        result.append(self._item_to_finding(item))
                    except:
                        log.exception("Failed to create finding item")
            result.sort(key=lambda item: (SEVERITIES.index(item.severity), item.tool, item.title))
        return result

    @property
    def project_false_positive_findings(self):
        """ Returns project false positive findings """
        result = list()
        if self.config.get("group_by_endpoint", False):
            result.extend(self._group_findings_by_endpoints([
                item for item in self.context.findings \
                if item.get_meta("false_positive_finding", False) and \
                        not item.get_meta("excluded_finding", False)
            ]))
        else:
            for item in self.context.findings:
                if item.get_meta("false_positive_finding", False) and \
                        not item.get_meta("excluded_finding", False):
                    try:
                        result.append(self._item_to_finding(item))
                    except:
                        log.exception("Failed to create finding item")
            result.sort(key=lambda item: (SEVERITIES.index(item.severity), item.tool, item.title))
        return result

    @property
    def project_excluded_findings(self):
        """ Returns project excluded findings """
        result = list()
        if self.config.get("group_by_endpoint", False):
            result.extend(self._group_findings_by_endpoints([
                item for item in self.context.findings \
                if item.get_meta("excluded_finding", False)
            ]))
        else:
            for item in self.context.findings:
                if item.get_meta("excluded_finding", False):
                    try:
                        result.append(self._item_to_finding(item))
                    except:
                        log.exception("Failed to create finding item")
            result.sort(key=lambda item: (SEVERITIES.index(item.severity), item.tool, item.title))
        return result

    @property
    def project_errors(self):
        """ Returns project errors """
        result = list()
        for item in self.context.errors:
            result.append(HTMLReportError(
                tool=item.tool,
                title=item.error,
                description=markdown.markdown_to_html(item.details)
            ))
        result.sort(key=lambda item: (item.tool, item.title))
        return result
