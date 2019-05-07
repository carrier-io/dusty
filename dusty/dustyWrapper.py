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

import os
import re
import json
import base64
import urllib
import logging
import subprocess
import pkg_resources
from time import sleep, time
from datetime import datetime
from random import randrange
from zapv2 import ZAPv2

from dusty import constants as c
from dusty.utils import execute, find_ip, common_post_processing, id_generator
from dusty.data_model.nikto.parser import NiktoXMLParser
from dusty.data_model.nmap.parser import NmapXMLParser
from dusty.data_model.sslyze.parser import SslyzeJSONParser
from dusty.data_model.masscan.parser import MasscanJSONParser
from dusty.data_model.w3af.parser import W3AFXMLParser
from dusty.data_model.qualys.parser import QualysWebAppParser
from dusty.data_model.aemhacker.parser import AemOutputParser
from dusty.data_model.zap.parser import ZapJsonParser
from dusty.drivers.qualys import WAS


class DustyWrapper(object):
    @staticmethod
    def sslyze(config):
        tool_name = "SSlyze"
        exec_cmd = f'sslyze --regular --json_out=/tmp/sslyze.json --quiet {config["host"]}:{config["port"]}'
        execute(exec_cmd)
        result = SslyzeJSONParser("/tmp/sslyze.json", "SSlyze").items
        return tool_name, result

    @staticmethod
    def masscan(config):
        tool_name = "masscan"
        host = config["host"]
        result = list()
        if not (find_ip(host)):
            host = find_ip(str(execute(f'getent hosts {host}')[0]))
            if len(host) > 0:
                host = host[0].strip()
        if host:
            if config.get("exclusions", None):
                excluded_addon = f'--exclude-ports {config.get("exclusions", None)}'
            else:
                excluded_addon = ''
            ports = config.get("inclusions", "0-65535")
            exec_cmd = f'masscan {host} -p {ports} -pU:{ports} --rate 1000 -oJ /tmp/masscan.json {excluded_addon}'
            execute(exec_cmd.strip())
            result = MasscanJSONParser("/tmp/masscan.json", "masscan").items
        return tool_name, result

    @staticmethod
    def nikto(config):
        tool_name = "nikto"
        if os.path.exists("/tmp/nikto.xml"):
            os.remove("/tmp/nikto.xml")
        exec_cmd = f'perl nikto.pl {config.get("param", "")} -h {config["host"]} -p {config["port"]} ' \
                   f'-Format xml -output /tmp/nikto.xml -Save /tmp/extended_nikto'
        cwd = '/opt/nikto/program'
        execute(exec_cmd, cwd)
        result = NiktoXMLParser("/tmp/nikto.xml", "Nikto").items
        return tool_name, result

    @staticmethod
    def nmap(config):
        tool_name = "NMAP"
        excluded_addon = f'--exclude-ports {config.get("exclusions", None)}' if config.get("exclusions", None) else ""
        ports = config.get("inclusions", "0-65535")
        nse_scripts = config.get("nse_scripts", "ssl-date,http-mobileversion-checker,http-robots.txt,http-title,"
                                                "http-waf-detect,http-chrono,http-headers,http-comments-displayer,"
                                                "http-date")
        exec_cmd = f'nmap -PN -p{ports} {excluded_addon} ' \
                   f'--min-rate 1000 --max-retries 0 --max-rtt-timeout 200ms ' \
                   f'{config["host"]}'
        res = execute(exec_cmd)
        tcp_ports = ''
        udp_ports = ''
        for each in re.findall(r'([0-9]*/[tcp|udp])', str(res[0])):
            if '/t' in each:
                tcp_ports += f'{each.replace("/t", "")},'
            elif '/u' in each:
                udp_ports += f'{each.replace("/u", "")},'
        ports = f"-pT:{tcp_ports[:-1]}" if tcp_ports else ""
        ports += f" -pU:{udp_ports[:-1]}" if udp_ports else ""
        if not ports:
            return (tool_name, [])
        params = config.get("params", "-v -sVA")
        exec_cmd = f'nmap {params} {ports} ' \
                   f'--min-rate 1000 --max-retries 0 ' \
                   f'--script={nse_scripts} {config["host"]} -oX /tmp/nmap.xml'
        execute(exec_cmd)
        result = NmapXMLParser('/tmp/nmap.xml', "NMAP").items
        return tool_name, result

    @staticmethod
    def w3af(config):
        tool_name = "w3af"
        config_file = config.get("config_file", "/tmp/w3af_full_audit.w3af")
        w3af_execution_command = f'w3af_console -y -n -s {config_file}'
        with open(config_file, 'r') as f:
            config_content = f.read()
        if '{target}' in config_content:
            config_content = config_content.format(
                target=f'{config.get("protocol")}://{config.get("host")}:{config.get("port")}',
                output_section=c.W3AF_OUTPUT_SECTION)
        with open(config_file, 'w') as f:
            f.write(config_content)
        execute(w3af_execution_command)
        result = W3AFXMLParser("/tmp/w3af.xml", "w3af").items
        return tool_name, result

    @staticmethod
    def qualys(config):
        tool_name = "qualys_was"
        qualys_scanner_type = config.get("qualys_scanner_type", "EXTERNAL").upper()
        # TODO : think on optimization or unification of Qualys pools for Internal scanners
        qualys_scanner = config.get("qualys_scanner", '')
        qualys_scanners_pool = config.get("scanners_pool", '')
        if qualys_scanners_pool:
            qualys_scanners_pool = randrange(1, int(qualys_scanners_pool)+1)  # randrange specifics
        qualys_profile_id = config.get("qualys_profile_id", None)
        qualys_template_id = config.get("qualys_template_id", None)
        if not (qualys_profile_id or qualys_template_id):
            raise RuntimeError("Qualys configuration invalid")
        if config.get("random_name", None):
            project_name = f"{config.get('project_name')}_{id_generator(8)}"
        else:
            project_name = config.get('project_name')
        target = f'{config.get("protocol")}://{config.get("host")}:{config.get("port")}'
        project_id = None
        auth_id = None
        scan_id = None
        report_id = None
        try:
            qualys = WAS()
            ts = datetime.utcfromtimestamp(int(time())).strftime('%Y-%m-%d %H:%M:%S')
            logging.info("Qualys: searching for existing project")
            project_id = qualys.search_for_project(project_name)
            if qualys_scanner_type == 'INTERNAL':
                scanner_appliance = f"<type>{qualys_scanner_type}</type>" \
                                    f"<friendlyName>{qualys_scanner}{qualys_scanners_pool}</friendlyName>"
            else:
                scanner_appliance = f"<type>{qualys_scanner_type}</type>"
            if not project_id:
                logging.info("Qualys: creating webapp")
                project_id = qualys.create_webapp_request(
                    project_name, target, qualys_profile_id,
                    excludes=config.get("exclude", None)
                )
            if not project_id:
                raise RuntimeError("Something went wrong and project wasn't found and created")
            if config.get("auth_script", None):
                logging.info("Qualys: creating auth record")
                auth_id = qualys.create_auth_record(
                    project_name, ts,
                    config.get("auth_script"),
                    config.get("auth_login", ""),
                    config.get("auth_password", "")
                )
                if not auth_id:
                    raise RuntimeError("Auth record was not created")
                qualys.add_auth_record(project_id, project_name, auth_id)
            logging.info("Qualys: starting scan")
            scan_id = qualys.start_scan(project_name, ts, project_id, qualys_profile_id, scanner_appliance, auth_record_id=auth_id)
            if not scan_id:
                raise RuntimeError("Scan haven't been started")
            logging.info("Qualys: waiting for scan to finish")
            while not qualys.scan_status(scan_id):
                sleep(c.QUALYS_STATUS_CHECK_INTERVAL)
            # qualys.download_scan_report(scan_id)
            logging.info("Qualys: requesting report")
            report_id = qualys.request_report(project_name, ts, scan_id, project_id, qualys_template_id)
            if not report_id:
                raise RuntimeError("Request report failed")
            logging.info("Qualys: waiting for report to be created")
            while not qualys.get_report_status(report_id):
                sleep(c.QUALYS_STATUS_CHECK_INTERVAL)
            logging.info("Qualys: downloading report")
            qualys.download_report(report_id)
        finally:
            if report_id:
                logging.info("Qualys: deleting report")
                qualys.delete_asset("report", report_id)
            if scan_id:
                logging.info("Qualys: deleting scan")
                qualys.delete_asset("wasscan", scan_id)
            if auth_id:
                logging.info("Qualys: deleting authentication record")
                qualys.delete_asset("webappauthrecord", auth_id)
            if project_id:
                project_scans = qualys.count_scans_in_project(project_id)
                logging.debug("Qualys: found %d active scans in webapp", project_scans)
                if not project_scans:
                    logging.info("Qualys: deleting webapp")
                    qualys.delete_asset("webapp", project_id)
        logging.info("Qualys: processing results")
        result = QualysWebAppParser("/tmp/qualys.xml", "qualys_was").items
        return tool_name, result

    @staticmethod
    def burp(config):
        tool_name = "burp"
        print(config)
        return tool_name, []

    @staticmethod
    def aemhacker(config):
        tool_name = "AEM_Hacker"
        aem_hacker_output = execute(f'aem-wrapper.sh -u {config.get("protocol")}://{config.get("host")}:{config.get("port")} --host {config.get("scanner_host", "127.0.0.1")} --port {config.get("scanner_port", "4444")}')[0].decode('utf-8')
        result = AemOutputParser(aem_hacker_output).items
        return tool_name, result

    @staticmethod
    def zap(config):
        # Nested functions
        def _wait_for_completion(condition, status, message, interval=10):
            """ Watch progress """
            current_status = status()
            logging.info(message, current_status)
            while condition():
                sleep(interval)
                next_status = status()
                if next_status != current_status:
                    logging.info(message, next_status)
                current_status = next_status
        # ZAP wrapper
        tool_name = "ZAP"
        results = list()
        # Start ZAP daemon in background (no need for supervisord)
        logging.info("Starting ZAP daemon")
        zap_daemon = subprocess.Popen([
            "/usr/bin/java", "-Xmx499m",
            "-jar", "/opt/zap/zap.jar",
            "-daemon", "-port", "8091", "-host", "0.0.0.0",
            "-config", "api.key=dusty",
            "-config", "api.addrs.addr.regex=true",
            "-config", "api.addrs.addr.name=.*",
            "-config", "ajaxSpider.browserId=htmlunit"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        zap_api = ZAPv2(
            apikey="dusty",
            proxies={
                "http": "http://127.0.0.1:8091",
                "https": "http://127.0.0.1:8091"
            }
        )
        # Wait for zap to start
        zap_started = False
        for _ in range(600):
            try:
                logging.info("Started ZAP %s", zap_api.core.version)
                zap_started = True
                break
            except IOError:
                sleep(1)
        if not zap_started:
            logging.error("ZAP failed to start")
            zap_daemon.kill()
            zap_daemon.wait()
            return tool_name, results
        # Format target URL
        proto = config.get("protocol")
        host = config.get("host")
        port = config.get("port")
        target = f"{proto}://{host}"
        if (proto == "http" and int(port) != 80) or \
                (proto == "https" and int(port) != 443):
            target = f"{target}:{port}"
        logging.info("Scanning target %s", target)
        # Setup context
        logging.info("Preparing context")
        zap_context_name = "dusty"
        zap_context = zap_api.context.new_context(zap_context_name)
        # Setup context inclusions and exclusions
        zap_api.context.include_in_context(zap_context_name, f".*{re.escape(host)}.*")
        for include_regex in config.get("include", list()):
            zap_api.context.include_in_context(zap_context_name, include_regex)
        for exclude_regex in config.get("exclude", list()):
            zap_api.context.exclude_from_context(zap_context_name, exclude_regex)
        if config.get("auth_script", None):
            # Load our authentication script
            zap_api.script.load(
                scriptname="zap-selenium-login.js",
                scripttype="authentication",
                scriptengine="Oracle Nashorn",
                filename=pkg_resources.resource_filename(
                    "dusty", "templates/zap-selenium-login.js"
                ),
                scriptdescription="Login via selenium script"
            )
            # Enable use of laoded script with supplied selenium-like script
            zap_api.authentication.set_authentication_method(
                zap_context,
                "scriptBasedAuthentication",
                urllib.parse.urlencode({
                    "scriptName": "zap-selenium-login.js",
                    "Script": base64.b64encode(
                        json.dumps(
                            config.get("auth_script")
                        ).encode("utf-8")
                    ).decode("utf-8")
                })
            )
            # Add user to context
            zap_user = zap_api.users.new_user(zap_context, "dusty_user")
            zap_api.users.set_authentication_credentials(
                zap_context,
                zap_user,
                urllib.parse.urlencode({
                    "Username": config.get("auth_login", ""),
                    "Password": config.get("auth_password", ""),
                    "type": "UsernamePasswordAuthenticationCredentials"
                })
            )
            # Enable added user
            zap_api.users.set_user_enabled(zap_context, zap_user, True)
            # Setup auth indicators
            if config.get("logged_in_indicator", None):
                zap_api.authentication.set_logged_in_indicator(
                    zap_context, config.get("logged_in_indicator")
                )
            if config.get("logged_out_indicator", None):
                zap_api.authentication.set_logged_out_indicator(
                    zap_context, config.get("logged_out_indicator")
                )
        # Setup scan policy
        scan_policy_name = "Default Policy"
        scan_policies = [
            item.strip() for item in config.get("scan_types", "all").split(",")
        ]
        # Disable globally blacklisted rules
        for item in c.ZAP_BLACKLISTED_RULES:
            zap_api.ascan.set_scanner_alert_threshold(
                id=item,
                alertthreshold="OFF",
                scanpolicyname=scan_policy_name
            )
            zap_api.pscan.set_scanner_alert_threshold(
                id=item,
                alertthreshold="OFF"
            )
        if "all" not in scan_policies:
            # Disable all scanners first
            for item in zap_api.ascan.scanners(scan_policy_name):
                zap_api.ascan.set_scanner_alert_threshold(
                    id=item["id"],
                    alertthreshold="OFF",
                    scanpolicyname=scan_policy_name
                )
            # Enable scanners from suite
            for policy in scan_policies:
                for item in c.ZAP_SCAN_POCILICES.get(policy, []):
                    zap_api.ascan.set_scanner_alert_threshold(
                        id=item,
                        alertthreshold="DEFAULT",
                        scanpolicyname=scan_policy_name)
        # Spider
        logging.info("Spidering target: %s", target)
        if config.get("auth_script", None):
            scan_id = zap_api.spider.scan_as_user(
                zap_context, zap_user, target, recurse=True, subtreeonly=True
            )
        else:
            scan_id = zap_api.spider.scan(target)
        _wait_for_completion(
            lambda: int(zap_api.spider.status(scan_id)) < 100,
            lambda: int(zap_api.spider.status(scan_id)),
            "Spidering progress: %d%%"
        )
        # Wait for passive scan
        _wait_for_completion(
            lambda: int(zap_api.pscan.records_to_scan) > 0,
            lambda: int(zap_api.pscan.records_to_scan),
            "Passive scan queue: %d items"
        )
        # Ajax Spider
        logging.info("Ajax spidering target: %s", target)
        if config.get("auth_script", None):
            scan_id = zap_api.ajaxSpider.scan_as_user(
                zap_context_name, "dusty_user", target, subtreeonly=True
            )
        else:
            scan_id = zap_api.ajaxSpider.scan(target)
        _wait_for_completion(
            lambda: zap_api.ajaxSpider.status == 'running',
            lambda: int(zap_api.ajaxSpider.number_of_results),
            "Ajax spider found: %d URLs"
        )
        # Wait for passive scan
        _wait_for_completion(
            lambda: int(zap_api.pscan.records_to_scan) > 0,
            lambda: int(zap_api.pscan.records_to_scan),
            "Passive scan queue: %d items"
        )
        # Active scan
        logging.info("Active scan against target %s", target)
        if config.get("auth_script", None):
            scan_id = zap_api.ascan.scan_as_user(
                target, zap_context, zap_user, recurse=True,
                scanpolicyname=scan_policy_name
            )
        else:
            scan_id = zap_api.ascan.scan(
                target,
                scanpolicyname=scan_policy_name
            )
        _wait_for_completion(
            lambda: int(zap_api.ascan.status(scan_id)) < 100,
            lambda: int(zap_api.ascan.status(scan_id)),
            "Active scan progress: %d%%"
        )
        # Wait for passive scan
        _wait_for_completion(
            lambda: int(zap_api.pscan.records_to_scan) > 0,
            lambda: int(zap_api.pscan.records_to_scan),
            "Passive scan queue: %d items"
        )
        # Get report
        logging.info("Scan finished. Processing results")
        zap_report = zap_api.core.jsonreport()
        if os.environ.get("debug", False):
            with open("/tmp/zap.json", "wb") as report_file:
                report_file.write(zap_report.encode("utf-8"))
        # Stop zap
        zap_daemon.kill()
        zap_daemon.wait()
        # Parse JSON
        results.extend(ZapJsonParser(zap_report, tool_name).items)
        pkg_resources.cleanup_resources()
        return tool_name, results
