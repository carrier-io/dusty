import datetime

from influxdb import InfluxDBClient
from dusty.utils import define_jira_priority


class InfluxReport(object):
    def __init__(self, global_results, other_results, created_jira_tickets, default_config):
        self.host = default_config['influx']['host']
        self.port = default_config['influx'].get('port', 8086)
        self.db = default_config['influx'].get('db', 'prodsec')
        self.login = default_config['influx'].get('login', '')
        self.password = default_config['influx'].get('password', '')
        self.project_name = default_config['project_name']
        self.environment = default_config['project_name']
        self.test_type = default_config['project_name']
        self.created_jira_tickets = created_jira_tickets
        self.open_issues = len(self.created_jira_tickets)
        self.execution_time = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        self.results = global_results
        self.results_by_severity = self.sort_results_by_severity()
        self.results_by_severity['new_in_jira'] = self.get_new_jira_issues()
        self.results_by_severity['total_in_jira'] = self.open_issues
        self.client = InfluxDBClient(self.host, self.port, username=self.login,
                                     password=self.password, database=self.db)
        self._ingest_active_errors()

    def sort_results_by_severity(self):
        results = dict()
        for each in self.results:
            priority = define_jira_priority(each.finding['severity'])
            if priority not in results:
                results[priority] = 0
            results[priority] += 1
        return results

    def get_new_jira_issues(self):
        i = 0
        for issue in self.created_jira_tickets:
            i += 1 if issue['new']  else 0
        return i

    def sort_results_by_issue_type(self):
        # TODO: implement with canonical issue naming
        pass

    def out_of_compliance_issues(self):
        # TODO: implement with compliance policy
        pass

    def _ingest_active_errors(self):
        stats = {
            "measurement": "stats",
            "time": self.execution_time,
            "tags": {
                'test_name': self.test_type,
                'type': self.test_type,
                'project': self.project_name
            },
            "fields": self.results_by_severity
        }
        self.client.write(stats)
        jira_issues = []
        for issue in self.created_jira_tickets:
            issue = {
                "measurement": "errors",
                "time": self.execution_time,
                "tags": {
                    'test_name': self.test_type,
                    'type': self.test_type,
                    'project': self.project_name
                },
                "fields": {
                    'priority': issue['priority'],
                    'status': issue['status'],
                    'link': issue['link'],
                    'created': datetime.datetime.strptime(issue['open_date'],
                                                          '%Y-%m-%dT%H:%M:%S.%f%z').strftime('%d %b %Y %H:%M'),
                    'description': issue['description'],
                    'assignee': issue['assignee']
                }
            }
            jira_issues.append(issue)
        self.client.write(stats)



