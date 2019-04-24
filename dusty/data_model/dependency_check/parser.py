__author__ = 'arozumenko'
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
from dusty.utils import cwe_to_severity
from jsonpath_rw import parse


class DependencyCheckParser(object):
    ATTACK_VECTOR_MAPPING = {
        "accessVector": "AV",
        "accessComplexity": "AC",
        "authenticationr>": "Au",
        "confidentialImpact": "C",
        "integrityImpact": "I",
        "availabilityImpact": "A",
        "privilegesRequired": "PR",
        "userInteraction": "UI",
        "scope": "S",
        "confidentialityImpact": "C",
        "attackVector": "AV",
        "attackComplexity": "AC"
    }

    def __init__(self, filename, test):
        self.items = []
        data = load(open(filename))
        expr = parse("dependencies[*].vulnerabilities.`parent`")

        for item in expr.find(data):
            title = f"Vulnerable dependency {item.value['fileName']}"
            description = f"{item.value.get('description', '')}"
            _severity, steps_to_reproduce = self.steps_to_reproduce(item)
            severity = cwe_to_severity(_severity)
            file_path = item.value['filePath']
            self.items.append(Finding(title=title, tool='dependency_check',
                                      active=False, verified=False, description=description,
                                      severity=severity, numerical_severity=severity,
                                      mitigation=False, impact=False, references=False,
                                      file_path=file_path, url='N/A', steps_to_reproduce=steps_to_reproduce,
                                      static_finding=True))

    def steps_to_reproduce(self, item):
        steps = []
        max_priority = 0

        for each in item.value['vulnerabilities']:
            _max = max([each.get("cvssv2", {"score": 0})["score"], each.get("cvssv3", {'baseScore': 0})['baseScore']])
            if max_priority < _max:
                max_priority = _max
            step = f"<pre>{each['name']} \n\n Description: {each['description']}\n\n"
            if 'cvssv2' in each:
                cvss2_vector = self._calculate_vector(each['cvssv2'])
                step += f"cvssv2: " \
                    f"{cwe_to_severity(each['cvssv2']['score'])}(f{each['cvssv2']['score']})\n" \
                    f"Attack Vector: {cvss2_vector}"

            if 'cvssv3' in each:
                cvss3_vector = self._calculate_vector(each['cvssv3'])
                step += f"\ncvssv3: " \
                    f"{cwe_to_severity(each['cvssv2']['score'])}(f{each['cvssv2']['score']})\n" \
                    f"Attack Vector: {cvss3_vector}"
            if 'references' in each:
                step += '\n\nReferences:\n'
                for ref in each['references']:
                    step += f"Name: {ref.get('name', '')}\n " \
                        f"Link: {ref.get('url', '')}\n " \
                        f"Source: {ref.get('source', '')}\n\n"
            steps.append(f"{step}</pre>")
        return max_priority, steps

    def _calculate_vector(self, item):
        _vector = ''
        for key, value in item.items():
            if key in self.ATTACK_VECTOR_MAPPING:
                _vector += f"/{self.ATTACK_VECTOR_MAPPING[key]}:{value[0]}"
        return _vector
