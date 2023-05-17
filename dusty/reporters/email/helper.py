#!/usr/bin/python3
# coding=utf-8

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
    Email helper
"""

import ssl
import smtplib
import traceback

from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from dusty.tools import log
from dusty.models.error import Error


class EmailHelper:
    """ Helps to send email """

    def __init__(self, context, server, login, password, port=587, timeout=30):  # pylint: disable=R0913
        self.context = context
        self.server = server
        self.port = port
        self.timeout = timeout
        self.login = login
        self.password = password
        self.connection = None

    def connect(self):
        """ Establish connection to SMTP server """
        try:
            self.connection = smtplib.SMTP(self.server, self.port, timeout=self.timeout)
            self.connection.ehlo()
            self.connection.starttls(context=ssl.create_default_context())
            self.connection.ehlo()
            self.connection.login(self.login, self.password)
        except ssl.SSLError:
            log.warning("SSL error, retrying with unverified SSL context")
            self.connection = smtplib.SMTP(self.server, self.port, timeout=self.timeout)
            self.connection.ehlo()
            self.connection.starttls(context=ssl._create_unverified_context())  # pylint: disable=W0212
            self.connection.ehlo()
            self.connection.login(self.login, self.password)
        except smtplib.SMTPServerDisconnected:
            log.warning("Seems like SMTP with TSL didn't work, trying with SMTP_SSL")
            self.connection = smtplib.SMTP_SSL(
                host=self.server, port=self.port, timeout=self.timeout
            )
            self.connection.ehlo()
            self.connection.login(self.login, self.password)
        except:  # pylint: disable=W0702
            log.exception("Failed to connect to SMTP server")
            error = Error(
                tool="EMail",
                error="Failed to connect to SMTP server",
                details=f"```\n{traceback.format_exc()}\n```"
            )
            self.context.errors.append(error)
            if self.connection:
                self.connection.quit()

    def send(self, mail_to, subject, html_body="", attachments=None, mail_from=...):  # pylint: disable=R0913
        """ Send mail """
        message = MIMEMultipart("alternative")
        #
        if mail_from is not ...:
            message["From"] = mail_from
        else:
            message["From"] = self.login
        #
        message["To"] = ", ".join(mail_to)
        message["Subject"] = subject
        message.attach(MIMEText(html_body, "html"))
        if attachments:
            if isinstance(attachments, str):
                attachments = [attachments]
            for item in attachments:
                if isinstance(item, tuple):
                    filepath, filename = item
                else:
                    filepath = item
                    filename = item.split('/')[-1]
                with open(filepath, "rb") as file:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(file.read())
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f"attachment; filename= {filename}"
                )
                message.attach(part)
        try:
            self.connect()
            self.connection.sendmail(message["From"], mail_to, message.as_string())
        except:  # pylint: disable=W0702
            log.exception("Failed to send email")
            error = Error(
                tool="EMail",
                error="Failed to send email",
                details=f"```\n{traceback.format_exc()}\n```"
            )
            self.context.errors.append(error)
        finally:
            if self.connection:
                self.connection.quit()

    def send_with_cc(self, mail_to, mail_cc, subject, html_body="", attachments=None, mail_from=...):  # pylint: disable=R0913,C0301
        """ Send mail """
        message = MIMEMultipart("alternative")
        #
        if mail_from is not ...:
            message["From"] = mail_from
        else:
            message["From"] = self.login
        #
        message["From"] = self.login
        message["To"] = ", ".join(mail_to)
        message["Cc"] = ", ".join(mail_cc)
        message["Subject"] = subject
        message.attach(MIMEText(html_body, "html"))
        if attachments:
            if isinstance(attachments, str):
                attachments = [attachments]
            for item in attachments:
                if isinstance(item, tuple):
                    filepath, filename = item
                else:
                    filepath = item
                    filename = item.split('/')[-1]
                with open(filepath, "rb") as file:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(file.read())
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f"attachment; filename= {filename}"
                )
                message.attach(part)
        try:
            self.connect()
            self.connection.sendmail(message["From"], mail_to + mail_cc, message.as_string())
        except:  # pylint: disable=W0702
            log.exception("Failed to send email")
            error = Error(
                tool="EMail",
                error="Failed to send email",
                details=f"```\n{traceback.format_exc()}\n```"
            )
            self.context.errors.append(error)
        finally:
            if self.connection:
                self.connection.quit()
