import defusedxml.lxml as lxml
from lxml import etree
from urllib.parse import urlparse
from markdownify import markdownify as md

from dusty.data_model.canonical_model import Endpoint, DefaultModel as Finding


class QualysWebAppParser(object):
    def __init__(self, file, test):
        self.items = self.qualys_webapp_parser(file, test)

    def qualys_webapp_parser(self, qualys_xml_file, test):
        parser = etree.XMLParser(remove_blank_text=True, no_network=True, recover=True)
        d = etree.parse(qualys_xml_file, parser)

        r = d.xpath('/WAS_WEBAPP_REPORT/RESULTS/WEB_APPLICATION/VULNERABILITY_LIST/VULNERABILITY')
        # r = d.xpath('/WAS_SCAN_REPORT/RESULTS/VULNERABILITY_LIST/VULNERABILITY')
        l = d.xpath('/WAS_WEBAPP_REPORT/RESULTS/WEB_APPLICATION/INFORMATION_GATHERED_LIST/INFORMATION_GATHERED')
        # l = d.xpath('/WAS_SCAN_REPORT/RESULTS/INFORMATION_GATHERED_LIST/INFORMATION_GATHERED')

        master_list = []

        for issue in r:
            master_list += self.issue_r(issue, d, test, "vul")

        for issue in l:
            master_list += self.issue_r(issue, d, test, "info")

        return master_list

    def issue_r(self, raw_row, vuln, test, issueType):
        ret_rows = []
        issue_row = {}

        _gid = raw_row.findtext('QID')
        _temp = issue_row
        param = None
        payload = None
        ep = None
        if issueType == "vul":
            url = raw_row.findtext('URL')
            param = raw_row.findtext('PARAM')
            payload = raw_row.findtext('PAYLOADS/PAYLOAD/PAYLOAD')
            parts = urlparse(url)

            ep = Endpoint(protocol=parts.scheme,
                          host=parts.netloc,
                          path=parts.path,
                          query=parts.query,
                          fragment=parts.fragment,
                          product=test.engagement.product)

        r = vuln.xpath('/WAS_WEBAPP_REPORT/GLOSSARY/QID_LIST/QID')

        for vuln_item in r:
            if vuln_item is not None:
                if vuln_item.findtext('QID') == _gid:
                    _temp['vuln_name'] = vuln_item.findtext('TITLE')
                    _temp['vuln_solution'] = vuln_item.findtext('SOLUTION')
                    _temp['vuln_description'] = md(vuln_item.findtext('DESCRIPTION'))
                    _temp['impact'] = md(vuln_item.findtext('IMPACT'))
                    _temp['CVSS_score'] = vuln_item.findtext('CVSS_BASE')
                    _temp['Severity'] = vuln_item.findtext('SEVERITY')

                    if _temp['Severity'] is not None:
                        if float(_temp['Severity']) == 1:
                            _temp['Severity'] = "Info"
                        elif float(_temp['Severity']) == 2:
                            _temp['Severity'] = "Low"
                        elif float(_temp['Severity']) == 3:
                            _temp['Severity'] = "Medium"
                        elif float(_temp['Severity']) == 4:
                            _temp['Severity'] = "High"
                        else:
                            _temp['Severity'] = "Critical"

                    if issueType == "vul":
                        finding = Finding(title=_temp['vuln_name'], mitigation=_temp['vuln_solution'],
                                          description=_temp['vuln_description'], param=param, payload=payload,
                                          severity=_temp['Severity'], impact=_temp['impact'], tool="QualysWAS")

                        finding.unsaved_endpoints = list()
                        if ep:
                            finding.unsaved_endpoints.append(ep)
                    else:
                        finding = Finding(title=_temp['vuln_name'], mitigation=_temp['vuln_solution'],
                                          description=_temp['vuln_description'], param=param, payload=payload,
                                          severity=_temp['Severity'], impact=_temp['impact'], tool="QualysWAS")
                    ret_rows.append(finding)
        return ret_rows

