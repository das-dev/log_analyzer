#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import os
import gzip
import json
import argparse

from string import Template
from datetime import datetime
from statistics import median, mean
from collections import defaultdict


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

DEFAULT_PATH_TO_CONFIG = '/usr/local/etc/config.json'
DEFAULT_CONFIG = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log"
}

FILENAME_PATTERN = r'^nginx-access-ui.log-(?P<date>\d*)(?P<ext>.gz)?$'
IP_ADDR = rf'(?:[\.\dA-Fa-f:]*)'
REMOTE_ADDR = rf'((?P<remote_addr>{IP_ADDR})|-)'
REMOTE_USER = r'((?P<remote_user>\w*)|-)'
HTTP_X_REAL_IP = rf'((?P<http_x_real_ip>{IP_ADDR})|-)'
TIME_LOCAL = r'(\[(?P<time_local>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]|-)'
REQUEST = r'\"((?:[A-Z]*) (?P<url>\S*) (?:[A-Z\/\.\d]*)|.)\"'
STATUS = r'((?P<status>\d{3})|-)'
BODY_BYTES_SENT = r'((?P<body_bytes_sent>\d*)|-)'
HTTP_REFERER = r'\"((?P<http_referer>.*?)|-)\"'
HTTP_USER_AGENT = r'\"((?P<http_user_agent>.*?)|-)\"'
HTTP_X_FORWARDED_FOR = r'\"((?P<http_x_forwarded_for>.*?)|-)\"'
HTTP_X_REQUEST_ID = r'\"((?P<http_x_request_id>.*?)|-)\"'
HTTP_X_RB_USER = r'\"((?P<http_x_rb_user>\w*?)|-)\"'
REQUEST_TIME = r'((?P<request_time>[\d\.]*)|-)'
LOG_FORMAT_PATTERN = f'{REMOTE_ADDR} {REMOTE_USER}  {HTTP_X_REAL_IP} {TIME_LOCAL} {REQUEST} ' \
                     f'{STATUS} {BODY_BYTES_SENT} {HTTP_REFERER} ' \
                     f'{HTTP_USER_AGENT} {HTTP_X_FORWARDED_FOR} {HTTP_X_REQUEST_ID} {HTTP_X_RB_USER} ' \
                     f'{REQUEST_TIME}'


def parse_date(date_string, fmt='%d.%m.%Y'):
    try:
        return datetime.strptime(date_string, fmt)
    except (TypeError, ValueError):
        return None


class NginxLogManager:
    pattern = FILENAME_PATTERN

    def __init__(self, log_dir):
        self.log_dir = log_dir

    def get_last_log(self):
        logs = sorted(self._scan_log_dir(), key=lambda log: log['log_date'])
        if logs:
            return logs[-1]

    def _scan_log_dir(self):
        if not os.path.isdir(self.log_dir):
            return

        for filename in os.listdir(self.log_dir):
            pathname = os.path.join(self.log_dir, filename)
            if not os.path.isfile(pathname):
                continue

            file_data = self._parse_filename(filename)
            if 'date' not in file_data:
                continue

            yield {'pathname': pathname, 'ext': file_data.get('ext'), 'log_date': file_data.get('date')}

    @classmethod
    def _parse_filename(cls, filename):
        match = re.match(cls.pattern, filename)
        if not match:
            return {}

        date = parse_date(match.groupdict().get('date'), '%Y%m%d')
        if not date:
            return {}
        return {'date': date, 'ext': match.groupdict().get('ext')}


class NginxLogParser:
    log_format_pattern = LOG_FORMAT_PATTERN

    def __init__(self, pathname, ext):
        self.pathname = pathname
        self.ext = ext

    def parse(self):
        records = self._read_log()
        for record in records:
            record_data = self._parse_log_record(record)
            if not record_data:
                continue

            yield record_data

    def _read_log(self):
        log_reader = self._read_plain_log
        if self.ext == '.gz':
            log_reader = self._read_gzipped_log

        for line in log_reader():
            yield line

    def _read_plain_log(self):
        with open(self.pathname) as fl:
            for line in fl.readlines():  # TODO: reading line by line
                yield line.rstrip('\n')

    def _read_gzipped_log(self):
        with gzip.open(self.pathname, 'rb') as gz:
            for line in gz.readlines():  # TODO: reading line by line
                yield line.decode('utf8').rstrip('\n')

    def _parse_log_record(self, record):
        match = re.match(self.log_format_pattern, record)
        if not match:
            return

        record_data = {
            'url': match.groupdict().get('url'),
            'request_time': match.groupdict().get('request_time')
        }
        return record_data


class NginxLogStat:
    def __init__(self, log_data, report_size=None):
        self.log_data = log_data
        self.report_size = report_size
        self.total_count = 0
        self.total_request_time = 0

    def make_stat(self):
        for url, stat in self._prepare_stat():
            request_time_per_url = sum(stat['request_time'])
            url_stat = {  # TODO: format values
                'url': url,
                'count': stat['count'],
                'count_perc': stat['count'] * 100 / self.total_count,
                'time_sum': request_time_per_url,
                'time_perc': request_time_per_url * 100 / self.total_request_time,
                'time_avg': mean(stat['request_time']),
                'time_max': max(stat['request_time']),
                'time_med': median(sorted(stat['request_time']))
            }
            yield url_stat

    def _prepare_stat(self):
        urls_stat = self._make_urls_stat().items()
        urls_stat = sorted(urls_stat, key=lambda item: -max(item[1]['request_time']))
        return urls_stat[:self.report_size] if self.report_size else urls_stat

    def _make_urls_stat(self):
        urls_stat = defaultdict(lambda: {'count': 0, 'request_time': []})
        for record in self.log_data:
            url = record.get('url')
            if not url:
                continue

            request_time = record.get('request_time')
            if not request_time:
                continue

            request_time = float(request_time)
            self.total_request_time += request_time
            self.total_count += 1
            urls_stat[url]['count'] += 1
            urls_stat[url]['request_time'].append(request_time)
        return urls_stat


class NginxLogReport:
    def __init__(self, log_stat, log_date):
        self.log_stat = log_stat
        self.log_date = log_date

    def make_report(self, report_dir):
        with open('report.html') as fl:
            template = fl.read()
        table_json = json.dumps(list(self.log_stat))
        report = Template(template).safe_substitute(table_json=table_json)
        filename = f'report-{self.log_date.strftime("%Y.%m.%d")}.html'
        if not os.path.isdir(report_dir):
            os.mkdir(report_dir)
        pathname = os.path.join(report_dir, filename)
        with open(pathname, 'w') as fl:
            fl.write(report)


class Config(dict):
    def __init__(self, default_config=None):
        super().__init__()
        self.update(default_config or {})

    def merge_external(self, pathname):
        external = self._parse_external(pathname)
        self.update(external)

    def _parse_external(self, pathname):
        with open(pathname) as fl:
            json_config = fl.read()

        return json.loads(json_config)


class NginxLogAnalyzer:
    def run(self, config_path):
        config = Config(DEFAULT_CONFIG)
        if config_path:
            config.merge_external(config_path)

        last_log = NginxLogManager(config['LOG_DIR']).get_last_log()
        if not last_log:
            return

        log_data = NginxLogParser(last_log['pathname'], last_log['ext']).parse()
        log_stat = NginxLogStat(log_data, config['REPORT_SIZE']).make_stat()
        NginxLogReport(log_stat, last_log['log_date']).make_report(config['REPORT_DIR'])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    config_help = f'path to config. Default: {DEFAULT_PATH_TO_CONFIG}'
    parser.add_argument('--config', type=str, const=DEFAULT_PATH_TO_CONFIG, default=None, nargs='?', help=config_help)
    args = parser.parse_args()
    NginxLogAnalyzer().run(args.config)
