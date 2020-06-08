# -*- coding: utf-8 -*-
import itertools
import os
import gzip
import shutil
import datetime
import unittest
import subprocess

import log_analyzer

APP_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'log_analyzer.py')
LOG_FILENAME_TEMPLATE = 'nginx-access-ui.log-{date}'
LOG_RECORD_TEMPLATE = '- -  - [{time_local}] "GET /url/1 HTTP/1.1" - - "-" "-" "-" "-" "-" {request_time}'
LOG_RECORD_INCORRECT_TEMPLATE = '[{time_local}] "GET /url/1 HTTP/1.1" {request_time}'
NOW = datetime.datetime.now(tz=datetime.timezone.utc)
TOMORROW = NOW + datetime.timedelta(days=1)
AFTER_TOMORROW = NOW + datetime.timedelta(days=2)


class TestHelper:
    FAKE_REPORT_CONTENT = 'fake report content'

    def __init__(self):
        self.config = log_analyzer.DEFAULT_CONFIG
        self.test_pathnames = [self.config['LOG_DIR'], self.config['REPORT_DIR']]

    def make_log_file(self, records, log_date=NOW, ext=''):
        basename = LOG_FILENAME_TEMPLATE.format(date=log_date.strftime('%Y%m%d'))
        pathname = os.path.join(self.config['LOG_DIR'], f'{basename}{ext}')
        reader = gzip.open if ext == '.gz' else open
        with reader(pathname, 'wb') as fl:
            fl.write('\n'.join(records).encode())

    def make_test_dirs(self):
        for path in self.test_pathnames:
            try:
                os.mkdir(path)
            except FileExistsError:
                continue

    def drop_test_dirs(self):
        for path in self.test_pathnames:
            shutil.rmtree(path)

    def create_fake_report(self, pathname):
        with open(pathname, 'w') as fl:
            fl.write(self.FAKE_REPORT_CONTENT)

    def make_report_pathname(self, report_date):
        return os.path.join(self.config["REPORT_DIR"], f'report-{report_date.strftime("%Y.%m.%d")}.html')

    def generate_log_records(self, records_data, template=LOG_RECORD_TEMPLATE):
        for time_local, request_time in records_data:
            time_local = time_local.strftime('%d/%b/%Y:%H:%M:%S %z')
            log_record = template.format(time_local=time_local, request_time=request_time)
            yield log_record


class LogAnalyzerDefaultConfigTest(unittest.TestCase):
    RECORD_DATA = [(NOW, .111)]

    def setUp(self):
        self.helper = TestHelper()
        self.helper.make_test_dirs()

    def tearDown(self):
        self.helper.drop_test_dirs()

    def test_do_not_make_a_report_without_log_file(self):
        console = subprocess.run(['python3', APP_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertFalse(os.path.isfile(self.helper.make_report_pathname(TOMORROW)))
        self.assertTrue(b'Not found logs for analysis' in console.stderr)

    def test_do_not_make_a_report_from_incorrect_logs(self):
        records = self.helper.generate_log_records(self.RECORD_DATA * 8)
        incorrect_records = self.helper.generate_log_records(self.RECORD_DATA * 2, LOG_RECORD_INCORRECT_TEMPLATE)
        records = itertools.chain(records, incorrect_records)
        self.helper.make_log_file(records, log_date=TOMORROW, ext='.gz')
        console = subprocess.run(['python3', APP_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertFalse(os.path.isfile(self.helper.make_report_pathname(TOMORROW)))
        self.assertTrue(b'Most of the analyzed logs could not be parsed' in console.stderr)

    def test_make_a_report_for_latest_log(self):
        records = self.helper.generate_log_records(self.RECORD_DATA * 10)
        self.helper.make_log_file(records, log_date=TOMORROW, ext='.gz')
        subprocess.run(['python3', APP_PATH])
        self.assertTrue(os.path.isfile(self.helper.make_report_pathname(TOMORROW)))

    def test_make_a_report_for_new_latest_log(self):
        records = self.helper.generate_log_records(self.RECORD_DATA * 10)
        self.helper.make_log_file(records, log_date=AFTER_TOMORROW, ext='.gz')
        subprocess.run(['python3', APP_PATH])
        self.assertTrue(os.path.isfile(self.helper.make_report_pathname(AFTER_TOMORROW)))

    def test_do_not_make_a_report_that_is_already_exists(self):
        pathname = self.helper.make_report_pathname(TOMORROW)
        records = self.helper.generate_log_records(self.RECORD_DATA * 10)
        self.helper.make_log_file(records, log_date=TOMORROW, ext='.gz')
        self.helper.create_fake_report(pathname)
        console = subprocess.run(['python3', APP_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with open(pathname) as fl:
            self.assertEqual(fl.read(), self.helper.FAKE_REPORT_CONTENT)
        self.assertTrue(b'The latest log has already been analyzed' in console.stderr)


if __name__ == '__main__':
    unittest.main()
