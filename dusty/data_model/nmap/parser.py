from xml.dom import NamespaceErr
import lxml.etree as le
from dusty.data_model.canonical_model import Endpoint, DefaultModel as Finding

__author__ = 'patriknordlen'
# Modified for Dusty by arozumenko


class NmapXMLParser(object):
    def __init__(self, file, test):
        parser = le.XMLParser(resolve_entities=False, huge_tree=True)
        nscan = le.parse(file, parser)
        root = nscan.getroot()

        if 'nmaprun' not in root.tag:
            raise NamespaceErr("This doesn't seem to be a valid Nmap xml file.")
        dupes = {}
        hostInfo = ""

        for host in root.iter("host"):
            ip = host.find("address[@addrtype='ipv4']").attrib['addr']
            fqdn = None
            if host.find("hostnames/hostname[@type='PTR']") is not None:
                fqdn = host.find("hostnames/hostname[@type='PTR']").attrib['name']

            for os in root.iter("os"):
                if ip is not None:
                    hostInfo += "IP Address: %s\n" % ip
                if fqdn is not None:
                    fqdn += "FQDN: %s\n" % ip
                for osv in os.iter('osmatch'):
                    if 'name' in osv.attrib:
                        hostInfo += "Host OS: %s\n" % osv.attrib['name']
                    if 'accuracy' in osv.attrib:
                        hostInfo += "Accuracy: {0}%\n".format(osv.attrib['accuracy'])
                hostInfo += "\n"
            for portelem in host.xpath("ports/port[state/@state='open']"):
                port = portelem.attrib['portid']
                protocol = portelem.attrib['protocol']

                title = f"Open port: {ip}:{port}/{protocol}"
                description = hostInfo
                description += f"Port: {port}\n"
                serviceinfo = ""

                if portelem.find('service') is not None:
                    if 'product' in portelem.find('service').attrib:
                        serviceinfo += "Product: %s\n" % portelem.find('service').attrib['product']

                    if 'version' in portelem.find('service').attrib:
                        serviceinfo += "Version: %s\n" % portelem.find('service').attrib['version']

                    if 'extrainfo' in portelem.find('service').attrib:
                        serviceinfo += "Extra Info: %s\n" % portelem.find('service').attrib['extrainfo']

                    description += serviceinfo

                description += '\n\n'

                severity = "Info"

                dupe_key = f'{port}_{protocol}_{ip}'
                print(dupe_key)
                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    if description is not None:
                        find.description += description
                else:
                    find = Finding(title=title,
                                   tool="NMAP",
                                   test=test,
                                   active=False,
                                   verified=False,
                                   description=description,
                                   severity=severity,
                                   numerical_severity=Finding.get_numerical_severity(severity))
                    find.unsaved_endpoints.append(f'{ip}:{port}/{protocol}')
                    dupes[dupe_key] = find
        self.items = dupes.values()
