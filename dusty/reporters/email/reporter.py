#!/usr/bin/python3
# coding=utf-8
# pylint: disable=I0011,E0401

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
    Reporter: email
"""

from jinja2 import Environment, PackageLoader, select_autoescape

from dusty.tools import log
from dusty.models.module import DependentModuleModel
from dusty.models.reporter import ReporterModel

from . import constants
from .presenter import EMailPresenter
from .helper import EmailHelper


class Reporter(DependentModuleModel, ReporterModel):
    """ Report findings from scanners """

    def __init__(self, context):
        """ Initialize reporter instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["reporters"][__name__.split(".")[-2]]

    def report(self):
        """ Report """
        log.info("Sending mail to %s", self.config.get("mail_to"))
        presenter = EMailPresenter(self.context, self.config)
        # Prepare email
        environment = Environment(
            loader=PackageLoader(
                "dusty",
                f"{'/'.join(__name__.split('.')[1:-1])}/data"
            ),
            autoescape=select_autoescape(["html", "xml"])
        )
        template = environment.get_template("email.html")
        html_body = template.render(presenter=presenter)
        # Send email
        helper = EmailHelper(
            self.context,
            self.config.get("server"),
            self.config.get("login"),
            self.config.get("password"),
            int(self.config.get("port", constants.DEFAULT_SERVER_PORT))
        )
        mail_to = [item.strip() for item in self.config.get("mail_to").split(",")]
        mail_cc = [item.strip() for item in self.config.get("mail_cc", "").split(",")]
        if mail_cc:
            helper.send_with_cc(
                mail_to, mail_cc, presenter.subject,
                html_body=html_body, attachments=presenter.attachments
            )
        else:
            helper.send(
                mail_to, presenter.subject, html_body=html_body, attachments=presenter.attachments
            )

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(len(data_obj), "server", "smtp.office365.com", comment="SMTP server host")
        data_obj.insert(len(data_obj), "port", "587", comment="(optional) SMTP server port")
        data_obj.insert(
            len(data_obj), "login", "some_username@example.com", comment="SMTP server login"
        )
        data_obj.insert(
            len(data_obj), "password", "SomeSecurePassword", comment="SMTP server password"
        )
        data_obj.insert(
            len(data_obj),
            "mail_to", "me@example.com, not_me@example.com", comment="List of email addresses"
        )
        data_obj.insert(
            len(data_obj),
            "mail_cc", "me@example.com, not_me@example.com", comment="List of CC email addresses"
        )
        data_obj.insert(
            len(data_obj),
            "subject", "My awesome project staging DAST zap scanning #1 results",
            comment="(optional) Custom email subject"
        )
        data_obj.insert(
            len(data_obj),
            "body", "The following application was scanned: My awesome project (staging)",
            comment="(optional) Custom email body first line"
        )
        data_obj.insert(
            len(data_obj),
            "additional_text", "",
            comment="(optional) Custom email body additional text"
        )
        data_obj.insert(
            len(data_obj),
            "attachments", "/path/to/file.1, /path/to/file.2",
            comment="(optional) Additional custom attachments. Also supports YAML list syntax"
        )
        data_obj.insert(
            len(data_obj),
            "text_only", False,
            comment="(optional) Text-only emai (do not include information about results/errors)"
        )

    @staticmethod
    def validate_config(config):
        """ Validate config """
        required = ["server", "login", "password", "mail_to"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def run_after():
        """ Return optional depencies """
        return ["html", "jira"]

    @staticmethod
    def get_name():
        """ Reporter name """
        return "EMail"

    @staticmethod
    def get_description():
        """ Reporter description """
        return "EMail reporter"
