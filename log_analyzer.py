#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import os
import sys
import gzip
import json
import logging
import argparse

from string import Template
from datetime import datetime
from statistics import median, mean
from collections import defaultdict

DIR_PATH = os.path.dirname(os.path.realpath(__file__))
TEMPLATE_DIR = os.path.join(DIR_PATH, 'templates')
DEFAULT_PATH_TO_CONFIG = '/usr/local/etc/config.json'
DEFAULT_CONFIG = {
    'REPORT_SIZE': 1000,
    'REPORT_DIR': './reports',
    'LOG_DIR': './log',
    'ERROR_THRESHOLD': .1
}

# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

FILENAME_PATTERN = r'^nginx-access-ui.log-(?P<date>\d+)(?P<ext>.gz)?$'
IP_ADDR = rf'(?:[\.\dA-Fa-f:]*)'
REMOTE_ADDR = rf'((?P<remote_addr>{IP_ADDR})|-)'
REMOTE_USER = r'((?P<remote_user>\w*)|-)'
HTTP_X_REAL_IP = rf'((?P<http_x_real_ip>{IP_ADDR})|-)'
TIME_LOCAL = r'(\[(?P<time_local>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]|-)'
REQUEST = r'\"((?:[A-Z]*) (?P<url>\S+) (?:[A-Z\/\.\d]*)|.)\"'
STATUS = r'((?P<status>\d{3})|-)'
BODY_BYTES_SENT = r'((?P<body_bytes_sent>\d*)|-)'
HTTP_REFERER = r'\"((?P<http_referer>.*?)|-)\"'
HTTP_USER_AGENT = r'\"((?P<http_user_agent>.*?)|-)\"'
HTTP_X_FORWARDED_FOR = r'\"((?P<http_x_forwarded_for>.*?)|-)\"'
HTTP_X_REQUEST_ID = r'\"((?P<http_x_request_id>.*?)|-)\"'
HTTP_X_RB_USER = r'\"((?P<http_x_rb_user>\w*?)|-)\"'
REQUEST_TIME = r'((?P<request_time>[\d\.]+)|-)'
LOG_FORMAT_PATTERN = f'{REMOTE_ADDR} {REMOTE_USER}  {HTTP_X_REAL_IP} {TIME_LOCAL} {REQUEST} ' \
                     f'{STATUS} {BODY_BYTES_SENT} {HTTP_REFERER} ' \
                     f'{HTTP_USER_AGENT} {HTTP_X_FORWARDED_FOR} {HTTP_X_REQUEST_ID} {HTTP_X_RB_USER} ' \
                     f'{REQUEST_TIME}'


class NginxLogManager:
    pattern = FILENAME_PATTERN

    def __init__(self, log_dir):
        self.log_dir = log_dir

    def get_latest_log(self):
        latest_log = None
        for log in self._scan_log_dir():
            if not latest_log or log['log_date'] > latest_log['log_date']:
                latest_log = log
        return latest_log

    def _scan_log_dir(self):
        try:
            files = os.listdir(self.log_dir)
        except FileNotFoundError:
            return

        for filename in files:
            file_data = self._parse_filename(filename)
            if not file_data:
                continue

            file_data['pathname'] = os.path.join(self.log_dir, filename)
            yield file_data

    @classmethod
    def _parse_filename(cls, filename):
        match = re.match(cls.pattern, filename)
        if not match:
            return

        date = match.groupdict().get('date')
        try:
            date = datetime.strptime(date, '%Y%m%d')
        except (ValueError, TypeError):
            return
        return {'log_date': date, 'ext': match.groupdict().get('ext')}


class NginxLogParser:
    log_format_pattern = LOG_FORMAT_PATTERN

    def __init__(self, pathname, ext=None):
        self.pathname = pathname
        self.ext = ext

    def parse(self):
        for record in self._read_log():
            yield self._parse_log_record(record)

    def _read_log(self):
        open_log = gzip.open if self.ext == '.gz' else open
        with open_log(self.pathname, 'rb') as log:
            for line in log:
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
    def __init__(self, log_data):
        self.log_data = log_data
        self.total_count = 0
        self.total_request_time = 0
        self.records_count = 0
        self.not_parsed_count = 0
        self.prepared_data = self._prepare_data()

    def make_stat(self):
        for url, stat in self.prepared_data:
            request_time_per_url = sum(stat['request_time'])
            url_stat = {
                'url': url,
                'count': stat['count'],
                'count_perc': round(stat['count'] * 100 / self.total_count, 3),
                'time_sum': round(request_time_per_url, 3),
                'time_perc': round(request_time_per_url * 100 / self.total_request_time, 3),
                'time_avg': round(mean(stat['request_time']), 3),
                'time_max': max(stat['request_time']),
                'time_med': round(median(sorted(stat['request_time'])), 3)
            }
            yield url_stat

    def error_threshold_exceeded(self, error_threshold):
        try:
            return self.not_parsed_count / self.records_count > error_threshold
        except ZeroDivisionError:
            return False

    def _prepare_data(self):
        urls_stat = defaultdict(lambda: {'count': 0, 'request_time': []})
        for count, record in enumerate(self.log_data, 1):
            self.records_count = count
            not_parsed = not record or 'url' not in record or 'request_time' not in record
            if not_parsed:
                self.not_parsed_count += 1
                continue

            url = record['url']
            request_time = float(record['request_time'])
            self.total_request_time += request_time
            self.total_count += 1
            urls_stat[url]['count'] += 1
            urls_stat[url]['request_time'].append(request_time)
        return urls_stat.items()


class NginxLogReport:
    report_filename_template = 'report-{date}.html'
    report_date_format = '%Y.%m.%d'

    def __init__(self, log_stat, log_date):
        self.log_stat = log_stat
        self.log_date = log_date

    @classmethod
    def report_exists(cls, report_dir, log_date):
        report_date = log_date.strftime(cls.report_date_format)
        filename = cls.report_filename_template.format(date=report_date)
        pathname = os.path.join(report_dir, filename)
        return os.path.isfile(pathname)

    def make_report(self, report_dir, report_size=None):
        context = self._make_context(report_size)
        report = self._render_report(context)
        self._write_report(report, report_dir)

    def _make_context(self, report_size=None):
        log_stat = sorted(self.log_stat, key=lambda log: -log['time_sum'])
        if report_size:
            log_stat = log_stat[:report_size]
        return {'table_json': json.dumps(log_stat)}

    def _render_report(self, context):
        with open(os.path.join(TEMPLATE_DIR, 'report.html')) as fl:
            template = fl.read()
        return Template(template).safe_substitute(**context)

    def _write_report(self, report, report_dir):
        report_date = self.log_date.strftime(self.report_date_format)
        filename = self.report_filename_template.format(date=report_date)
        if not os.path.isdir(report_dir):
            os.mkdir(report_dir)
        pathname = os.path.join(report_dir, filename)
        with open(pathname, 'w') as fl:
            fl.write(report)


class Config(dict):
    def __init__(self, default_config=None):
        super().__init__()
        self.update(default_config or {})

    def merge_external(self, config_path):
        try:
            self.update(self._parse_config(config_path))
        except ValueError:
            raise ValueError('External config is incorrect')

    def _parse_config(self, config_path):
        json_config = self._read_config(config_path)
        if not json_config:
            return {}

        try:
            return json.loads(json_config)
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError('External config is incorrect', e.doc, e.pos)

    def _read_config(self, config_path):
        try:
            with open(config_path) as fl:
                return fl.read()
        except FileNotFoundError:
            raise FileNotFoundError('External config is missing')


class LogAnalyzer:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    def run(self):
        latest_log = NginxLogManager(self.config['LOG_DIR']).get_latest_log()
        if not latest_log:
            print('Not found logs for analysis')
            self.logger.info('Not found logs for analysis')
            return

        if NginxLogReport.report_exists(self.config['REPORT_DIR'], latest_log['log_date']):
            print('The latest log has already been analyzed')
            self.logger.info('The latest log has already been analyzed')
            return

        log_data = NginxLogParser(latest_log['pathname'], latest_log['ext']).parse()
        log_stat_maker = NginxLogStat(log_data)
        if log_stat_maker.error_threshold_exceeded(self.config['ERROR_THRESHOLD']):
            print('Most of the analyzed logs could not be parsed')
            self.logger.error('Most of the analyzed logs could not be parsed')
            return

        log_stat = log_stat_maker.make_stat()
        report_dir, report_size = self.config['REPORT_DIR'], self.config['REPORT_SIZE']
        NginxLogReport(log_stat, latest_log['log_date']).make_report(report_dir, report_size)


class Command:
    def handle(self):
        config = self._make_config()
        logging.basicConfig(
            format='[%(asctime)s] %(levelname).1s %(message)s',
            datefmt='%Y.%m.%d %H:%M:%S',
            filename=config.get('LOGGING_FILE'),
            level=logging.INFO
        )

        log_analyzer = LogAnalyzer(config, logging.getLogger())
        try:
            log_analyzer.run()
        except KeyboardInterrupt:
            log_analyzer.logger.exception('KeyboardInterrupt')
        except Exception as e:
            log_analyzer.logger.exception(e)
            print(e)

    def _make_config(self):
        args = self._parse_args()
        config = Config(DEFAULT_CONFIG)
        if not args.config:
            return config

        try:
            config.merge_external(args.config)
        except Exception as e:
            print(e, file=sys.stderr)
            sys.exit()

        return config

    def _parse_args(self):
        parser = argparse.ArgumentParser()
        config_help = f'path to config. Default: {DEFAULT_PATH_TO_CONFIG}'
        parser.add_argument('--config', type=str, const=DEFAULT_PATH_TO_CONFIG, default=None, nargs='?',
                            help=config_help)
        return parser.parse_args()


if __name__ == "__main__":
    Command().handle()
