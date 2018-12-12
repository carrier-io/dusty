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
