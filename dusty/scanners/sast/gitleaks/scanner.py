#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,E0401,W0702,W0703

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
    Scanner: gitleaks
"""

import os
import getpass
import subprocess
import shutil
import tempfile
import traceback
import pkg_resources
import dulwich

from dusty.tools import log
from dusty.commands import git_clone
from dusty.models.module import DependentModuleModel
from dusty.models.scanner import ScannerModel

from .parser import parse_findings


class Scanner(DependentModuleModel, ScannerModel):
    """ Scanner class """

    def __init__(self, context):
        """ Initialize scanner instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["scanners"][__name__.split(".")[-3]][__name__.split(".")[-2]]

    def execute(self):
        """ Run the scanner """
        # Squash commits (if needed)
        if self.config.get("squash_commits", None):
            # Rename old .git
            try:
                os.rename(
                    os.path.join(self.config.get("code"), ".git"),
                    os.path.join(self.config.get("code"), ".git.old")
                )
            except:
                log.debug("Failed to rename old .git: %s", traceback.format_exc())
            # Initialize new repo
            current_dir = os.getcwd()
            try:
                os.chdir(self.config.get("code"))
                # Patch dulwich to work without valid UID/GID
                dulwich.repo.__original__get_default_identity = dulwich.repo._get_default_identity  # pylint: disable=W0212
                dulwich.repo._get_default_identity = git_clone._dulwich_repo_get_default_identity  # pylint: disable=W0212
                # Set USERNAME if needed
                try:
                    getpass.getuser()
                except:  # pylint: disable=W0702
                    os.environ["USERNAME"] = "git"
                # Add current code
                repository = dulwich.porcelain.init(self.config.get("code"))
                repository._put_named_file(os.path.join("info", "exclude"), b"/.git.old/")  # pylint: disable=W0212
                dulwich.porcelain.add(repository)
                log.debug("Git repository status: %s", dulwich.porcelain.status(repository, True))
                dulwich.porcelain.commit(
                    repository,
                    b"Current project code", b"Carrier <dusty@localhost>"
                )
            finally:
                os.chdir(current_dir)
        # Make temporary files
        output_file_fd, output_file = tempfile.mkstemp(".json")
        log.debug("Output file: %s", output_file)
        os.close(output_file_fd)
        additional_options = list()
        if self.config.get("redact_offenders", None):
            additional_options.append("--redact")
        if self.config.get("folder_scan", None):
            additional_options.append("--no-git")
        # Use custom rules
        if self.config.get("use_custom_rules", None):
            custom_rules_path = self.config.get("custom_rules_path", None)
            if custom_rules_path:
                config_path = custom_rules_path
            else:
                config_path = pkg_resources.resource_filename(
                    "dusty",
                    f"{'/'.join(__name__.split('.')[1:-1])}/data/gitleaks.toml")
            additional_options.append("--config")
            additional_options.append(config_path)
            log.debug("Custom config path: %s", config_path)
        # Run task
        task = subprocess.run(
            [
                "gitleaks", "detect", "--source", self.config.get("code"), "--report-path", output_file
            ] + additional_options,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log.log_subprocess_result(task)
        # Parse findings
        parse_findings(output_file, self)
        # Save intermediates
        self.save_intermediates(output_file, task)
        # Revert commit squashing (if any)
        if self.config.get("squash_commits", None):
            shutil.rmtree(os.path.join(self.config.get("code"), ".git"))
            try:
                os.rename(
                    os.path.join(self.config.get("code"), ".git.old"),
                    os.path.join(self.config.get("code"), ".git")
                )
            except:
                log.debug("Failed to revert .git: %s", traceback.format_exc())

    def save_intermediates(self, output_file, task):
        """ Save scanner intermediates """
        if self.config.get("save_intermediates_to", None):
            log.info("Saving intermediates")
            base = os.path.join(self.config.get("save_intermediates_to"), __name__.split(".")[-2])
            try:
                # Make directory for artifacts
                os.makedirs(base, mode=0o755, exist_ok=True)
                # Save report
                shutil.copyfile(
                    output_file,
                    os.path.join(base, "report.json")
                )
                # Save output
                with open(os.path.join(base, "output.stdout"), "w") as output:
                    output.write(task.stdout.decode("utf-8", errors="ignore"))
                with open(os.path.join(base, "output.stderr"), "w") as output:
                    output.write(task.stderr.decode("utf-8", errors="ignore"))
            except:
                log.exception("Failed to save intermediates")

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(len(data_obj), "code", "/path/to/code", comment="scan target")
        data_obj.insert(
            len(data_obj), "squash_commits", False,
            comment="(optional) Make one commit with current code only"
        )
        data_obj.insert(
            len(data_obj), "show_offender_line", True,
            comment="(optional) Show lines with findings"
        )
        data_obj.insert(
            len(data_obj), "commit_line_limit", 15,
            comment="(optional) Limit number of commit lines in one finding. Default: 15"
        )
        data_obj.insert(
            len(data_obj), "redact_offenders", False,
            comment="(optional) Hide secrets in lines with findings"
        )
        data_obj.insert(
            len(data_obj), "hide_commit_author", False,
            comment="(optional) Hide information about commits and authors"
        )
        data_obj.insert(
            len(data_obj), "use_custom_rules", False,
            comment="(optional) Use custom detection rules"
        )
        data_obj.insert(
            len(data_obj), "custom_rules_path", "/path/to/rules",
            comment="(optional) Path to custom rules"
        )
        data_obj.insert(
            len(data_obj), "additional_text", "",
            comment="(optional) Additional text to add to description"
        )
        data_obj.insert(
            len(data_obj), "save_intermediates_to", "/data/intermediates/sast",
            comment="(optional) Save scan intermediates (raw results, logs, ...)"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["code"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def get_name():
        """ Module name """
        return "gitleaks"

    @staticmethod
    def get_description():
        """ Module description or help message """
        return "gitleaks scanning"
