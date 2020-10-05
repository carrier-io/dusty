#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,W1401,E0401,R0914,R0915,R0912,C0103

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
    Nmap XML parser

    Original author: patriknordlen
    Modified for Dusty 1.0 by: arozumenko
    Ported to Dusty 2.0 by: LifeDJIK
"""

import elementpath
from defusedxml.cElementTree import parse

from dusty.tools import log, url, markdown
from dusty.models.finding import DastFinding
from dusty.models.error import Error
from dusty.constants import SEVERITIES


def parse_findings(output_file, scanner):
    """ Parse findings (code from dusty 1.0) """
    log.debug("Parsing findings")
    nscan = parse(output_file)
    root = nscan.getroot()
    # Check validity
    if "nmaprun" not in root.tag:
        log.error("Exception during Nmap findings processing: invalid XML file")
        error = Error(
            tool=scanner.get_name(),
            error=f"Exception during Nmap findings processing",
            details=f"Output file doesn't seem to be a valid Nmap xml file."
        )
        scanner.errors.append(error)
        return
    dupes = dict()
    hostInfo = ""
    for host in root.iter("host"):
        ip = host.find("address[@addrtype='ipv4']").attrib["addr"]
        fqdn = None
        if host.find("hostnames/hostname[@type='PTR']") is not None:
            fqdn = host.find("hostnames/hostname[@type='PTR']").attrib["name"]
        #
        for os in root.iter("os"):
            if ip is not None:
                hostInfo += "IP Address: %s\n" % ip
            if fqdn is not None:
                fqdn += "FQDN: %s\n" % ip
            for osv in os.iter("osmatch"):
                if "name" in osv.attrib:
                    hostInfo += "Host OS: %s\n" % osv.attrib["name"]
                if "accuracy" in osv.attrib:
                    hostInfo += "Accuracy: {0}%\n".format(osv.attrib["accuracy"])
            hostInfo += "\n"
        #
        xpath_port_selector = "ports/port[state/@state='open']"
        if scanner.config.get("include_unfiltered", False):
            xpath_port_selector = "ports/port[state/@state=('open','unfiltered')]"
        #
        for portelem in elementpath.select(host, xpath_port_selector):
            port = portelem.attrib["portid"]
            protocol = portelem.attrib["protocol"]
            #
            title = f"Open port: {ip}:{port}/{protocol}"
            description = hostInfo
            description += f"Port: {port}\n"
            serviceinfo = ""
            #
            if portelem.find("service") is not None:
                if "product" in portelem.find("service").attrib:
                    serviceinfo += "Product: %s\n" % portelem.find("service").attrib["product"]
                #
                if "version" in portelem.find("service").attrib:
                    serviceinfo += "Version: %s\n" % portelem.find("service").attrib["version"]
                #
                if "extrainfo" in portelem.find("service").attrib:
                    serviceinfo += "Extra Info: %s\n" % portelem.find("service").attrib["extrainfo"]
                #
                description += serviceinfo
            #
            description += "\n\n"
            #
            dupe_key = f"{port}_{protocol}_{ip}"
            if dupe_key in dupes:
                find = dupes[dupe_key]
                if description is not None:
                    find["description"] += description
            else:
                find = {
                    "title": title,
                    "description": description,
                    "endpoints": list()
                }
                find["endpoints"].append(f"{ip}:{port}/{protocol}")
                dupes[dupe_key] = find
    # Create finding objects
    for item in dupes.values():
        finding = DastFinding(
            title=item["title"],
            description=markdown.markdown_escape(item["description"])
        )
        finding.set_meta("tool", scanner.get_name())
        finding.set_meta("severity", SEVERITIES[-1])
        # Endpoints (for backwards compatibility)
        endpoints = list()
        for entry in item["endpoints"]:
            endpoint = url.parse_url(entry)
            if endpoint in endpoints:
                continue
            endpoints.append(endpoint)
        finding.set_meta("endpoints", endpoints)
        log.debug(f"Endpoints: {finding.get_meta('endpoints')}")
        # Done
        scanner.findings.append(finding)
