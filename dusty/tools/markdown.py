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
    Markdown tools
"""

import re
import traceback
import markdown2
import inscriptis

from bs4 import BeautifulSoup
from dusty.tools import log


def markdown_to_html(text):
    """ Convert markdown to HTML """
    # Install markdown2 hooks to support "{panel}", "{code}" and "|| tables |"
    markdown2.Markdown.preprocess = _markdown2_preprocess
    markdown2.Markdown.postprocess = _markdown2_postprocess
    # Run markdown2
    return markdown2.markdown(text, extras=["tables", "wiki-tables", "fenced-code-blocks"])


def _markdown2_preprocess(self, text):  # pylint: disable=W0613
    # Handle {code}
    def _code_handler(item):
        return \
            "{code:title=" + \
            item.group("title") + \
            "|" + item.group("style") + \
            "}\n```\n"
    text = re.sub(
        r'{code:title=(?P<title>.*?)\|(?P<style>.*?)}',
        _code_handler,
        text
    )
    text = text.replace("{code}", "```\n{code}")
    # Handle || tables |
    def _table_panel_handler(item):
        return \
            "\n\n{panel:title=Instance:}\n" \
            f'{item.group("data")}\n' \
            "{panel}\n\n"
    text = re.sub(
        r'\n\n(?P<data>\|\|(.*?[\n]*?)+\|)\n\n',
        _table_panel_handler,
        text,
        flags=re.MULTILINE
    )
    def _table_item_handler(item):
        return \
            f'**{item.group("name")}**: {item.group("value")}'
    text = re.sub(
        r'\|\| \*(?P<name>.*?)\* \| (?P<value>.*?) \|',
        _table_item_handler,
        text
    )
    return text


def _markdown2_postprocess(self, text):  # pylint: disable=W0613
    # Handle {panel}
    def _panel_handler(item):
        return \
            f'<div class="card">' \
            f'<div class="card-header">{item.group("title")}</div><div class="card-body">'
    text = re.sub(
        r'(\<p\>)?\s*{panel:title=(?P<title>.*?):(?P<style>.*?)}\s*(\<\/p\>)?',
        _panel_handler,
        text
    )
    text = re.sub(
        r'(\<p\>)?\s*{panel}\s*(\<\/p\>)?',
        "</div></div>",
        text
    )
    # Handle {code}
    def _code_handler(item):
        return \
            f'<div class="card">' \
            f'<div class="card-header">{item.group("title")}</div><div class="card-body">'
    text = re.sub(
        r'(\<p\>)?\s*{code:title=(?P<title>.*?)\|(?P<style>.*?)}\s*(\<\/p\>)?',
        _code_handler,
        text
    )
    text = re.sub(
        r'(\<p\>)?\s*{code}\s*(\<\/p\>)?',
        "</div></div>",
        text
    )
    # Return result
    return text


def markdown_escape(string):
    """ Escape markdown special symbols """
    to_escape = [
        "\\", "`", "*", "_",
        "{", "}", "[", "]", "(", ")",
        "#", "|", "+", "-", ".", "!"
    ]
    for item in to_escape:
        string = string.replace(item, f"\\{item}")
    return string


def markdown_unescape(string):
    """ Un-escape markdown special symbols """
    to_escape = [
        "\\", "`", "*", "_",
        "{", "}", "[", "]", "(", ")",
        "#", "|", "+", "-", ".", "!"
    ]
    for item in to_escape:
        string = string.replace(f"\\{item}", item)
    return string


def markdown_table_escape(string):
    """ Escape markdown special symbols in tables """
    return markdown_escape(string).replace("\n", " ").replace("\r", " ")


def markdown_to_text(string):
    """ Convert markdown to plain text """
    return "".join(BeautifulSoup(markdown_to_html(string), "html.parser").findAll(text=True))


def html_to_text(html, escape=True):
    """ Convert HTML to markdown """
    try:
        text = inscriptis.get_text(html, display_links=True)
    except:  # pylint: disable=W0702
        log.debug("Exception during HTML to text conversion\n%s", traceback.format_exc())
        text = ""
    if escape:
        text = markdown_escape(text)
    return text
