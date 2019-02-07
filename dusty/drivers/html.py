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

import re
from os import path
from jinja2 import Environment, PackageLoader, select_autoescape


class HTMLReport(object):
    report_name = None

    def __init__(self, findings, config, report_path='/tmp/reports'):
        env = Environment(
            loader=PackageLoader('dusty', 'templates'),
            autoescape=select_autoescape(['html', 'xml'])
        )
        self.template = env.get_template('html_report_template.html')
        res = self.template.render(config=config, findings=findings)
        test_name = f'{config["project_name"]}-{config["environment"]}-{config["test_type"]}'
        self.report_name = path.join(report_path, f'TEST-{test_name}.html')
        with open(self.report_name, "w") as f:
            f.write(re.sub(r'[^\x00-\x7f]',r'', res))
        print(f"Generated report:  <reports folder>/TEST-{test_name}.html")

