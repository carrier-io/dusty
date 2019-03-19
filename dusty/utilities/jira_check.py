import argparse
from dusty.drivers.jira import JiraWrapper
from dusty.run import config_from_yaml, parse_jira_config
from dusty.utils import report_to_jira
from dusty.data_model.canonical_model import DefaultModel as Finding

__author__ = 'KarynaTaranova'

def main():
    parser = argparse.ArgumentParser(description='jira check')
    parser.add_argument('-d', '--delete', type=str, help="")
    parser.add_argument('-u', '--user', type=str, help="")
    parser.add_argument('-p', '--password', type=str, help="")
    args, unknown = parser.parse_known_args()
    if args.delete:
        ids = [item.strip() for item in args.delete.split(",")]
        default_config, test_configs = config_from_yaml()
        project = default_config.get('jira_service').project
        url = default_config.get('jira_service').url
        user = args.user if args.user else default_config.get('jira_service').user
        password = args.password if args.password else default_config.get('jira_service').password
        j = JiraWrapper(url, user, password, project)
        j.connect()
        try:
            for id in ids:
                j.client.issue(id).delete()
                print(f'Issue {args.delete} was deleted.')
        finally:
            j.client.close()
    else:
        default_config, test_configs = config_from_yaml()
        title = 'Carrier test. Please remove this ticket. It was created for testing purposes only.'
        test = 'Carrier'
        description = 'Please remove this ticket. \nIt was created for testing purposes only.'
        severity = 'Info'
        item = Finding(title=title, tool=test, active=False,
                       verified=False, description=description,
                       severity=severity)
        report_to_jira(default_config, [item])
        print('To delete created issue:\njira_check -s <test_name> -d <issue_key>\nOptional params:\n'
              'To specify user with an ability to delete tickets:\n-u user_name -p password')


if __name__ == "__main__":
    main()
