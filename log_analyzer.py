#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import os
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
REPORT_FILENAME_TEMPLATE = 'report-{date}.html'
REPORT_DATE_FORMAT = '%Y.%m.%d'
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

RE_FILENAME = r'^nginx-access-ui.log-(?P<date>\d+)(?P<ext>.gz)?$'
RE_REQUEST = r'\"((?:[A-Z]*) (?P<url>\S+) (?:[A-Z\/\.\d]*)|.)\"'
RE_REQUEST_TIME = r'((?P<request_time>[\d\.]+)|-)'
RE_LOG_FORMAT = rf'(\S*|-) (\S*|-)  (\S*|-) \[(.*|-)\] {RE_REQUEST} ' \
                     rf'(\S*|-) (\S*|-) \"(.*|-)\" ' \
                     rf'\"(.*|-)\" \"(.*|-)\" \"(.*|-)\" \"(.*|-)\" ' \
                     rf'{RE_REQUEST_TIME}'


def find_latest_log(log_dir, filename_pattern):
    try:
        files = os.listdir(log_dir)
    except FileNotFoundError:
        return

    latest_log = None
    for filename in files:
        pathname = os.path.join(log_dir, filename)
        if not os.path.isfile(pathname):
            continue

        match = re.match(filename_pattern, filename)
        if not match:
            continue

        date = match.groupdict().get('date')
        try:
            date = datetime.strptime(date, '%Y%m%d')
        except ValueError:
            continue

        if not latest_log or date > latest_log['log_date']:
            latest_log = {
                'log_date': date,
                'pathname': os.path.join(log_dir, filename),
                'ext': match.groupdict().get('ext')
            }
    return latest_log


class NginxLogParser:
    log_format_pattern = RE_LOG_FORMAT

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


def report_exists(report_dir, log_date):
    report_date = log_date.strftime(REPORT_DATE_FORMAT)
    filename = REPORT_FILENAME_TEMPLATE.format(date=report_date)
    pathname = os.path.join(report_dir, filename)
    return os.path.isfile(pathname)


class NginxLogReport:
    report_filename_template = REPORT_FILENAME_TEMPLATE
    report_date_format = REPORT_DATE_FORMAT

    def __init__(self, log_stat, log_date):
        self.log_stat = log_stat
        self.log_date = log_date

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


class LogAnalyzer:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    def run(self):
        latest_log = find_latest_log(self.config['LOG_DIR'], RE_FILENAME)
        if not latest_log:
            self.logger.info('Not found logs for analysis')
            return

        if report_exists(self.config['REPORT_DIR'], latest_log['log_date']):
            self.logger.info('The latest log has already been analyzed')
            return

        log_data = NginxLogParser(latest_log['pathname'], latest_log['ext']).parse()
        log_stat_maker = NginxLogStat(log_data)
        if log_stat_maker.error_threshold_exceeded(self.config['ERROR_THRESHOLD']):
            self.logger.error('Most of the analyzed logs could not be parsed')
            return

        log_stat = log_stat_maker.make_stat()
        report_dir, report_size = self.config['REPORT_DIR'], self.config['REPORT_SIZE']
        NginxLogReport(log_stat, latest_log['log_date']).make_report(report_dir, report_size)


def parse_args():
    parser = argparse.ArgumentParser()
    config_help = f'path to config. Default: {DEFAULT_PATH_TO_CONFIG}'
    parser.add_argument('--config', type=str, const=DEFAULT_PATH_TO_CONFIG, default=None, nargs='?',
                        help=config_help)
    return parser.parse_args()


def parse_config(config_path):
    with open(config_path) as fl:
        json_config = fl.read()
    if not json_config:
        return {}
    return json.loads(json_config)


def main(config_path):
    config = DEFAULT_CONFIG
    if config_path:
        config.update(parse_config(config_path))

    logging.basicConfig(
        format='[%(asctime)s] %(levelname).1s %(message)s',
        datefmt='%Y.%m.%d %H:%M:%S',
        filename=config.get('LOGGING_DIR'),
        level=logging.INFO
    )

    log_analyzer = LogAnalyzer(config, logging.getLogger())
    try:
        log_analyzer.run()
    except KeyboardInterrupt:
        log_analyzer.logger.exception('KeyboardInterrupt')
    except Exception as e:
        log_analyzer.logger.exception(e)


if __name__ == "__main__":
    args = parse_args()
    main(args.config)
