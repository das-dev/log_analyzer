#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

import re
import os

from datetime import datetime


config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log"
}


class NginxLogManager:
    pattern = r'nginx-access-ui.log-(?P<date>\d*)(.gz)?'

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
                yield {'filename': filename, 'date': date}

    def sort_logs(self, key=lambda log: log['date']):
        return sorted(self.scan_logs(), key=key)

    def get_last_log(self):
        logs = self.sort_logs()
        if not logs:
            return

        return logs[-1]


class NginxLogParser:
    def __init__(self, filename):
        self.filename = filename

    def parse(self):
        return self.filename


def main():
    report_dir = config.get('REPORT_DIR')
    last_log = NginxLogManager(config.get('LOG_DIR')).get_last_log()
    if last_log:
        log_data = NginxLogParser(last_log['filename']).parse()


if __name__ == "__main__":
    main()
