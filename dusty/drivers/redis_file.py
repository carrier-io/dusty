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

import redis
from os import sep


class RedisFile(object):
    def __init__(self, connection_string, html_report_file, xml_report_file):
        self.client = redis.Redis.from_url(connection_string)
        if html_report_file:
            self.set_key(html_report_file)
        if xml_report_file:
            self.set_key(xml_report_file)

    def set_key(self, filepath):
        with open(filepath, 'r') as f:
            self.client.set(filepath.split(sep)[-1], f.read())

    def get_key(self, filepath):
        with open(filepath, 'w') as f:
            f.write(self.client.get(filepath.split(sep)[-1]))
