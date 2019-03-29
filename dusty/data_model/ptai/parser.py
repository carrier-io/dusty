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


import os
import re
from bs4 import BeautifulSoup
from dusty import constants
from dusty.data_model.ptai_model import PTAIModel as Finding


__author__ = 'KarynaTaranova'


class PTAIScanParser(object):
    def __init__(self, filename, filtered_statuses=constants.PTAI_DEFAULT_FILTERED_STATUSES):
        """
        :param filename:
        :param filtered_statuses: str with statuses, separated ', '
        """
        file_path_descriptions_list = ['Уязвимый файл']

        def trim_blank_lines(line):
            blank_lines_patterns = ['\n( *\n)', '\n+']
            for pattern in blank_lines_patterns:
                finds = re.findall(pattern, line)
                for find in finds:
                    line = line.replace(find, '\n')
            return line

        def get_value_by_description(table_soap, descriptions):
            option_descriptions_soup = table_soap.select('td[class*="option-description"]')
            option_descriptions = [item.text for item in option_descriptions_soup]
            value_index = -1
            value = ''
            for description in descriptions:
                value_index = option_descriptions.index(description)
                if value_index >= 0:
                    break
            if value_index >= 0:
                option_values_soup = table_soap.select('td[class*="option-value"]')
                value = option_values_soup[value_index].text
            return value

        dupes = dict()
        self.items = []
        if not os.path.exists(filename):
            return
        soup = BeautifulSoup(open(filename, encoding="utf8"), 'html.parser')
        vulnerabilities_info = {}
        vulnerabilities_info_soup = soup.find_all('div', {'class': 'type-description'})
        for vulnerability_info_soup in vulnerabilities_info_soup:
            id = vulnerability_info_soup.find('a', {'class': 'glossary-anchor'}).attrs.get('id')
            vulnerabilities_info[id] = vulnerability_info_soup.text.replace(id, '')
        vulnerabilities_soup = soup.find_all('div', {'class': 'vulnerability'})
        for vulnerability_soup in vulnerabilities_soup:
            if filtered_statuses:
                skip_flag = False
                for filter_status in filtered_statuses:
                    status = vulnerability_soup.find_all('i', {'class': '{}-icon'.format(filter_status)})
                    if status:
                        skip_flag = True
                        break
                if skip_flag:
                    continue
            severity_level_soup = vulnerability_soup.select('div[class*="vulnerability-type-name-level-"]')
            title = ''
            file_path = ''
            short_file_path = ''
            if severity_level_soup:
                title = severity_level_soup[0].text
                # Get file path (strip line number if present)
                file_path = get_value_by_description(vulnerability_soup, file_path_descriptions_list).rsplit(' : ', 1)[0]
                if '\\' in file_path:
                    short_file_path = ' in ...\\' + file_path.split('\\')[-1]
                severity_classes_soup = severity_level_soup[0].attrs.get('class')
                for severity_class_soup in severity_classes_soup:
                    if 'vulnerability-type-name-level-' in severity_class_soup:
                        severity = severity_class_soup.split('-')[-1]
            vulnerability_link_info_soup = vulnerability_soup.find_all('a', {'class': 'vulnerability-description-link'})
            if vulnerability_link_info_soup:
                vulnerability_info_href = vulnerability_link_info_soup[0].attrs.get('href').replace('#', '')
                vulnerability_info = ''
                if vulnerability_info_href in vulnerabilities_info:
                    vulnerability_info = vulnerabilities_info[
                                             vulnerability_info_href][
                                         vulnerabilities_info[vulnerability_info_href].find(title) + len(title):]
            detail_info_soup = vulnerability_soup.find_all('table', {'class': 'vulnerability-detail-info'})
            detail_info_values = {}
            if detail_info_soup:
                detail_info_soup_tds = detail_info_soup[0].find_all('td')
                detail_info_values[detail_info_soup_tds[0].text] = detail_info_soup_tds[1].text
            functions = vulnerability_soup.find_all('div', {'class': 'vulnerability-info'})
            function_blocks_strs = []
            for function in functions:
                function_info_values = {}
                for tr in function.find_all('table', {'class': 'vulnerability-detail-info'})[0].find_all('tr'):
                    tds = tr.find_all('td')
                    if tds:
                        param = tds[0].text
                        if param.startswith('\n'):
                            param = param[1:]
                        value = ' '
                        if len(tds) == 2:
                            value = tds[1].text
                            if value.startswith('\n'):
                                value = value[1:]
                            if 'CWE' in value:
                                link_str_list = vulnerability_info[vulnerability_info.find(value.strip()):].split('\n')
                                link_info = [x.strip() for x in link_str_list if x.strip()]
                                if not link_info or link_info == ['.']:
                                    a_soup = tds[1].find_all('a')
                                    if a_soup:
                                        a_href = a_soup[0].attrs.get('href')
                                        a_text = a_soup[0].text
                                        if a_text.startswith('\n'):
                                            a_text = value[1:]
                                        link_info = [a_text.strip(), a_href]
                                    else:
                                        link_info = [' ']
                                value = ': '.join(link_info)
                        function_info_values[param] = trim_blank_lines(value)
                tables_lines = []
                tables_soup = function.find_all('div', {'class': 'data-flow-entry-root'})
                for table_soup in tables_soup:
                    lines = {}
                    header_file_name = table_soup.find_all('span', {'class': 'data-flow-entry-header-file-name'})[0].text
                    header_type = table_soup.find_all('span', {'class': 'data-flow-entry-header-type'})[0].text
                    code_lines_soup = table_soup.find_all('div', {'class': 'data-flow-entry-code-line-root'})
                    for code_line_soup in code_lines_soup:
                        line_number = code_line_soup.find_all('span', {'class': 'data-flow-entry-code-line-number'})[0].text
                        line_content = code_line_soup.find_all('pre', {'class': 'data-flow-entry-code-line-content'})[0]
                        line_text = line_content.text
                        bold_text = line_content.find('span', {'class': ['code-line-part-EntryPoint',
                                                                         'code-line-part-DataEntryPoint',
                                                                         'code-line-part-DataOperation',
                                                                         'code-line-part-VulnerableCode']})
                        if bold_text:
                            line_text = line_text + '      <------'
                        lines[line_number] = line_text
                    tables_lines.append({'lines': lines,
                                        'header_file_name': header_file_name,
                                        'header_type': header_type})
                #  format strings
                srt_code_blocks = []
                for table_lines in tables_lines:
                    table_markdown_str = '{{code:title={} - {}|borderStyle=solid}}  \n{}  \n{{code}}'
                    code_lines = ''
                    for key, value in table_lines['lines'].items():
                        code_lines += '{} {}  \n'.format(key, value)
                    srt_code_blocks.append(table_markdown_str.format(table_lines['header_file_name'],
                                                                table_lines['header_type'],
                                                                code_lines))
                data_flow_panel_str = ''
                for str_code_block in srt_code_blocks:
                    if data_flow_panel_str:
                        # add arrow
                        data_flow_panel_str += '  \n  \n|{}|  \n  \n'.format(chr(129147))
                    data_flow_panel_str += str_code_block
                function_info_values_str = ''
                for param, value in detail_info_values.items():
                    if param not in function_info_values:
                        value = value.replace('\n                       ', ': ')\
                                .replace('|', '&#124; ').replace('{', '\{').replace('}', '\}')
                        str_line = '  \n  \n|| *{}* | *{}* |'.format(param, value)
                        function_info_values_str = str_line
                for param, value in function_info_values.items():
                    value = value.replace('*', '\*').replace('|', '&#124; ').replace('{', '\}')\
                        .replace('}', '\}')
                    str_line = '|| *{}* | {} |'.format(param, value)
                    str_line = str_line.replace('  ', '')
                    function_info_values_str += '  \n' + str_line
                function_full_info_str = function_info_values_str + '\n  \n '
                if data_flow_panel_str:
                    function_full_info_str += '  \n {panel:title=Data Flow:|borderStyle=dashed|borderColor' \
                                             '=#ccc|titleBGColor=#F7D6C1|bgColor=#FFFFCE}  \n  \n' + data_flow_panel_str \
                                             + '  \n  \n {panel}  \n  \n'
                function_blocks_strs.append(function_full_info_str)
            description = 'h3. {}:  \n  \n{}  \n  \n'.format(title, vulnerability_info.strip())
            dup_key = title + ' in file: ' + file_path
            # Add finding data to de-duplication store
            if dup_key not in dupes:
                dupes[dup_key] = dict(
                    title=title + short_file_path,
                    description=description,
                    severity=severity.title(),
                    file_path=file_path,
                    function_blocks_strs=list()
                )
            # Add function blocks
            dupes[dup_key]["function_blocks_strs"].extend(function_blocks_strs)
        # Process items
        for item in dupes.values():
            comments = list()
            description = item.description
            for chunk in function_blocks_strs:
                if (len(description) + len(chunk)) < constants.JIRA_DESCRIPTION_MAX_SIZE:
                    description += '  \n  \n' + chunk
                elif not comments or (len(comments[-1]) + len(chunk)) > constants.JIRA_COMMENT_MAX_SIZE:
                    comments.append(chunk)
                else:  # Last comment can handle one more chunk
                    comments[-1] += '  \n  \n' + chunk
            self.items.append(Finding(
                title=item.title,
                tool='PTAI',
                active=False,
                verified=False,
                description=description,
                severity=item.severity,
                file_path=item.file_path,
                comments=comments,
                static_finding=True
            ))
