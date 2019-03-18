from dusty.run import config_from_yaml, parse_jira_config
from dusty.utils import report_to_jira
from dusty.data_model.canonical_model import DefaultModel as Finding

__author__ = 'KarynaTaranova'

def main():
    default_config, test_configs = config_from_yaml()
    title = 'Carrier test. Please remove this ticket. It was created for testing purposes only.'
    test = 'Carrier'
    description = 'Please remove this ticket. \nIt was created for testing purposes only.'
    severity = 'Info'
    item = Finding(title=title, tool=test, active=False,
                   verified=False, description=description,
                   severity=severity)
    report_to_jira(default_config, [item])

if __name__ == "__main__":
    main()