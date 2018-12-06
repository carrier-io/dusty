__author__ = 'aaronweaver'
# Modified for Dusty by arozumenko

from datetime import datetime
import json
from dusty.data_model.canonical_model import DefaultModel as Finding


class BrakemanParser(object):
    def __init__(self, filename, test):
        with open(filename, 'rb') as f:
            data = json.load(f)
        dupes = dict()
        find_date = data['scan_info']['start_time']

        for item in data["warnings"]:
            dupe_key = f"{item['warning_type']} in {item['file']}"

            if dupe_key not in dupes:
                dupes[dupe_key] = Finding(title=dupe_key,
                                          tool="brakeman",
                                          active=False,
                                          verified=False,
                                          description=item['message'],
                                          scanner_confidence=item['confidence'],
                                          severity=item['confidence'],
                                          references=item['link'],
                                          file_path=item["file"],
                                          line=item["line"],
                                          url='N/A',
                                          date=find_date,
                                          static_finding=True)
        self.items = dupes.values()
