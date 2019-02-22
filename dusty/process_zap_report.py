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

from dusty.utils import common_post_processing
from dusty.drivers.html import HTMLReport
from dusty.drivers.xunit import XUnitReport
from dusty.data_model.zap.parser import ZapXmlParser


def main():
    default_config = dict(
        project_name="demo",
        environment="demo",
        min_priority="Trivial",
        test_type="AuthenticatedScan",
        host="localhost",
        port="9090",
        html_report=dict(project_name="demo")
    )

    result = ZapXmlParser("/tmp/zap.xml", "ZAP").items
    filtered_result = common_post_processing(default_config, result, "ZAP")
    print(filtered_result)
    print(HTMLReport(filtered_result, default_config).report_name)
    print(XUnitReport(filtered_result, default_config).report_name)


if __name__ == "__main__":
    main()