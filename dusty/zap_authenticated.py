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

from time import time

from dusty.run import config_from_yaml, process_results
from dusty.utils import common_post_processing, execute
from dusty.data_model.zap.parser import ZapXmlParser


def main():
    start_time = time()
    default_config, _ = config_from_yaml()
    execute(f"zap-cli spider {default_config['protocol']}://{default_config['host']}:{default_config['port']}")
    execute(f"zap-cli active-scan --scanners all --recursive "
            f"{default_config['protocol']}://{default_config['host']}:{default_config['port']}")
    execute("zap-cli report -o /tmp/zap.xml -f xml")
    result = ZapXmlParser("/tmp/zap.xml", "ZAP").items
    filtered_result = common_post_processing(default_config, result, "ZAP")
    process_results(default_config, start_time, filtered_result)


if __name__ == "__main__":
    main()
