__author__ = 'aaronweaver'
# Modified for Dusty by arozumenko

from datetime import datetime
import json
from dusty.data_model.canonical_model import DefaultModel as Finding


class BanditParser(object):
    def __init__(self, filename, test):
        with open(filename, 'rb') as f:
            data = json.load(f)
        dupes = dict()
        find_date = None
        if "generated_at" in data:
            find_date = datetime.strptime(data["generated_at"], '%Y-%m-%dT%H:%M:%SZ').strftime("%Y-%m-%d %H:%M:%S")

        for item in data["results"]:
            impact = ''
            findingdetail = ''

            title = "Test Name: " + item["test_name"] + " Test ID: " + item["test_id"]

            ###### Finding details information ######
            findingdetail += "Filename: " + item["filename"] + "\n"
            findingdetail += "Line number: " + str(item["line_number"]) + "\n"
            findingdetail += "Issue Confidence: " + item["issue_confidence"] + "\n\n"
            findingdetail += "Code:\n"
            findingdetail += item["code"] + "\n"

            sev = item["issue_severity"]
            mitigation = item["issue_text"]
            references = item["test_id"]

            dupe_key = title + item["filename"] + str(item["line_number"])

            if dupe_key not in dupes:
                dupes[dupe_key] = Finding(title=title,
                                          tool="bandit",
                                          active=False,
                                          verified=False,
                                          description=findingdetail,
                                          severity= sev.title(),
                                          numerical_severity=Finding.get_numerical_severity(sev),
                                          mitigation=mitigation,
                                          impact=impact,
                                          references=references,
                                          file_path=item["filename"],
                                          line=item["line_number"],
                                          url='N/A',
                                          date=find_date,
                                          static_finding=True)
        self.items = dupes.values()
