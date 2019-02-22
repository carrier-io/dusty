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

import smtplib
import ssl
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class EmailWrapper(object):
    def __init__(self, smtp_server, login, password, port=None, receiver_emails=None,
                 subject=None, body=None):
        self.valid = True
        self.smtp_server = smtp_server
        self.login = login
        self.password = password
        self.port = port if port else 587
        self.receiver_emails = receiver_emails if receiver_emails else []
        self.subject = subject if subject else ''
        self.body = body if body else ''
        self.connect()
        self.server.quit()

    def connect(self):
        try:
            context = ssl.create_default_context()
            self.server = smtplib.SMTP(self.smtp_server, self.port)
            self.server.ehlo()
            self.server.starttls(context=context)
            self.server.ehlo()
            self.server.login(self.login, self.password)
        except ssl.SSLError:
            context = ssl._create_unverified_context()
            self.server = smtplib.SMTP(self.smtp_server, self.port)
            self.server.ehlo()
            self.server.starttls(context=context)
            self.server.ehlo()
            self.server.login(self.login, self.password)
        except Exception as e:
            self.valid = False
            print(e)
            if self.server:
                self.server.quit()

    def send(self, receiver_emails=None, subject=None, text_body='', html_body=None, html_style='',
             attachments=None):
        message = MIMEMultipart('alternative')
        message["From"] = self.login
        if receiver_emails:
            self.receiver_emails = receiver_emails
        message["To"] = ', '.join(self.receiver_emails)
        message["Subject"] = subject if subject else self.subject
        all_text = ''
        for text in [self.body, text_body]:
            all_text += text.replace('\n', '<br>') + '<br>'
        if html_body:
            all_text += html_body
        html = """\
            <html>
                <head>
                    <style>**style**</style>
                </head>
                <body>**body**</body>
            </html>
            """
        message.attach(MIMEText(html.replace('**body**', all_text).replace('**style**', html_style), 'html'))
        if attachments:
            if isinstance(attachments, str):
                attachments = [attachments]
            if isinstance(attachments, list):
                for attachment in attachments:
                    with open(attachment, "rb") as file_content:
                        part = MIMEBase("application", "octet-stream")
                        part.set_payload(file_content.read())
                    encoders.encode_base64(part)
                    part.add_header(
                        "Content-Disposition",
                        f"attachment; filename= {attachment.split('/')[-1]}",
                    )
                    message.attach(part)
        text = message.as_string()
        if self.valid:
            try:
                self.connect()
                self.server.sendmail(message["From"], self.receiver_emails, text)
                print('Sent emails to {}'.format(self.receiver_emails))
            except Exception as e:
                self.valid = False
                print(e)
            finally:
                self.server.quit()






