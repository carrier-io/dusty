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

from json import load
from dusty.data_model.canonical_model import DefaultModel as Finding


class MasscanJSONParser(object):
    def __init__(self, file, test):
        with open(file, "rb") as f:
            data = load(f)
        self.items = []
        for issue in data:
            title = f'Open port {issue["ports"][0]["port"]} found on {issue["ip"]}'
            self.items.append(Finding(title=title, tool="masscan",
                                      active=False, verified=False,
                                      description=title,
                                      severity="Info",
                                      endpoints=[f'{issue["ip"]}:{issue["ports"][0]["port"]}']))
