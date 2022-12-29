#!/usr/bin/python3
# coding=utf-8
# pylint: skip-file

#   Copyright 2019 getcarrier.io
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

"""
    Code from Dusty 1.0
"""

import json
import html

from dusty.tools import markdown

from . import constants


__author__ = 'KarynaTaranova'


class GitleaksScanParser(object):
    def __init__(self, data, scanner):
        dupes = dict()
        self.items = []

        try:
            data = json.load(open(data))
        except:
            return

        show_offender_line = scanner.config.get("show_offender_line", True)
        squash_commits = scanner.config.get("squash_commits", False) or scanner.config.get(
            "hide_commit_author", False)
        commit_line_limit = scanner.config.get("commit_line_limit", 15)

        for item in data:
            title = self.get_title(item)
            if title in dupes:
                if len(dupes[title]["commits"]) < commit_line_limit:
                    dupes[title]["commits"].append(
                        self.get_commit_info(item, show_offender_line, squash_commits))
                else:
                    dupes[title]["skipped_commits"] += 1
            else:
                dupes[title] = {
                    "description": ("\n\n**Tags:** ") + ", ".join(item.get('Tags')),
                    # "severity": item.get('severity'),
                    "date": item.get('Date'),
                    "rule": item.get('Description'),
                    "file_path": item.get('File'),
                    "skipped_commits": 0,
                    "commits": [self.get_commit_info(item, show_offender_line, squash_commits)]
                }
        commits_head = []
        commits_head.append("\n\n**Commits:**\n\n")
        if squash_commits:
            commits_head.append("| Line |")
            commits_head.append("| ---- |")
        else:
            commits_head.append("| Commit | Author | Line |")
            commits_head.append("| ------ | ------ | ---- |")
        for key, item in dupes.items():
            if len(item.get('commits')) == commit_line_limit:
                if squash_commits:
                    item["commits"].append(f"_And {item.get('skipped_commits')} more_")
                else:
                    item["commits"].append(f"_And {item.get('skipped_commits')} more_ | - | -")
            self.items.append({
                "title": key,
                "description": item.get("description") +
                               "\n".join(commits_head +
                               ["| {} |".format(line) for line in item.get('commits')]),
                "severity": constants.RULES_SEVERITIES.get(item.get('rule'), 'Critical'),
                "file_path": item.get('file_path'),
                "date": item.get('date')
            })

    def get_title(self, item):
        return f"{item.get('Description')} in {item.get('File')} file detected"

    def get_commit_info(self, item, show_offender_line, squash_commits):
        line = item.get("Match")
        if len(line) > 100:
            line = f"{line[:100]} ... (offender: {item.get('Secret')[:100]})"
        if squash_commits:
            return html.escape(markdown.markdown_table_escape(
                line if show_offender_line else "<hidden>"
            ))
        return " | ".join([
            html.escape(markdown.markdown_table_escape(item.get("Commit")[:8])),
            html.escape(markdown.markdown_table_escape(item.get("Author"))),
            html.escape(markdown.markdown_table_escape(
                line if show_offender_line else "<hidden>"
            ))
        ])
