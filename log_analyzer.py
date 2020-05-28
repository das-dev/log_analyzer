#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import re
import os
import gzip

from datetime import datetime


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

REMOTE_ADDR = r'((?P<remote_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|-)'
REMOTE_USER = r'((?P<remote_user>\w*)|-)'
HTTP_X_REAL_IP = r'((?P<http_x_real_ip>\w*)|-)'
TIME_LOCAL = r'(\[(?P<time_local>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]|-)'
REQUEST = r'\"((?P<request>.*?)|-)\"'
STATUS = r'((?P<status>\d{3})|-)'
BODY_BYTES_SENT = r'((?P<body_bytes_sent>\d*)|-)'
HTTP_REFERER = r'\"((?P<http_referer>.*?)|-)\"'
HTTP_USER_AGENT = r'\"((?P<http_user_agent>.*?)|-)\"'
HTTP_X_FORWARDED_FOR = r'\"((?P<http_x_forwarded_for>.*?)|-)\"'
HTTP_X_REQUEST_ID = r'\"((?P<http_x_request_id>.*?)|-)\"'
HTTP_X_RB_USER = r'\"((?P<http_x_rb_user>\w*?)|-)\"'
REQUEST_TIME = r'((?P<request_time>\d*\.\d{3})|-)'
LOG_FORMAT_PATTERN = f'{REMOTE_ADDR} {REMOTE_USER}  {HTTP_X_REAL_IP} {TIME_LOCAL} {REQUEST} ' \
                     f'{STATUS} {BODY_BYTES_SENT} {HTTP_REFERER} ' \
                     f'{HTTP_USER_AGENT} {HTTP_X_FORWARDED_FOR} {HTTP_X_REQUEST_ID} {HTTP_X_RB_USER} ' \
                     f'{REQUEST_TIME}'


class NginxLogManager:
    pattern = r'\Anginx-access-ui.log-(?P<date>\d*)(?P<ext>.gz)?\Z'

    def __init__(self, log_dir):
        self.log_dir = log_dir

    @classmethod
    def _parse_date(cls, filename):
        match = re.match(cls.pattern, filename)
        if not match or 'date' not in match.groupdict():
            return

        row_date = match.groupdict().get('date')
        return datetime.strptime(row_date, '%Y%m%d')

    def scan_logs(self):
        for filename in os.listdir(self.log_dir):
            date = self._parse_date(filename)
            if date:
                yield {'fullpath': os.path.join(self.log_dir, filename), 'date': date}

    def get_last_log(self):
        logs = sorted(self.scan_logs(), key=lambda log: log['date'])
        if not logs:
            return

        return logs[-1]


class NginxLogParser:
    def __init__(self, fullpath):
        self.fullpath = fullpath

    def _read_log(self):
        with gzip.open(self.fullpath, 'rb') as gz:
            return [line.decode('utf8') for line in gz.readlines()]

    def _parse_log_record(self, record):
        return re.match(LOG_FORMAT_PATTERN, record).groupdict()

    def parse(self):
        records = self._read_log()
        for record in records:
            yield self._parse_log_record(record)


def main():
    config = {
        "REPORT_SIZE": 1000,
        "REPORT_DIR": "./reports",
        "LOG_DIR": "./log"
    }
    last_log = NginxLogManager(config['LOG_DIR']).get_last_log()
    if not last_log:
        return

    log_data = NginxLogParser(last_log['fullpath']).parse()
    report_dir = config['REPORT_DIR']


if __name__ == "__main__":
    main()
