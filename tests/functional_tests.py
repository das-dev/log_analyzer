# -*- coding: utf-8 -*-
import os
import gzip
import shutil
import datetime
import unittest
import subprocess

import log_analyzer


LOG_FILENAME_TEMPLATE = 'nginx-access-ui.log-{date}'
LOG_RECORD_TEMPLATE = '- -  - [{time_local}] "GET /url/1 HTTP/1.1" - - "-" "-" "-" "-" "-" {request_time}'
NOW = datetime.datetime.now(tz=datetime.timezone.utc)
TOMORROW = NOW + datetime.timedelta(days=1)
AFTER_TOMORROW = NOW + datetime.timedelta(days=2)


class TestHelper:
    def __init__(self):
        self.config = log_analyzer.DEFAULT_CONFIG
        self.test_pathnames = [self.config['LOG_DIR'], self.config['REPORT_DIR']]

    def make_log_file(self, records_data, log_date=NOW, ext=''):
        try:
            os.mkdir(self.config['LOG_DIR'])
        except FileExistsError:
            pass

        basename = LOG_FILENAME_TEMPLATE.format(date=log_date.strftime('%Y%m%d'))
        pathname = os.path.join(self.config['LOG_DIR'], f'{basename}{ext}')
        lines = self._generate_log_records(records_data)
        reader = gzip.open if ext == '.gz' else open
        with reader(pathname, 'wb') as fl:
            fl.write('\n'.join(lines).encode())

    def drop_test_dirs(self):
        for path in self.test_pathnames:
            shutil.rmtree(path)

    def make_report_pathname(self, report_date):
        return os.path.join(self.config["REPORT_DIR"], f'report-{report_date.strftime("%Y.%m.%d")}.html')

    def _generate_log_records(self, records_data):
        for time_local, request_time in records_data:
            time_local = time_local.strftime('%d/%b/%Y:%H:%M:%S %z')
            log_record = LOG_RECORD_TEMPLATE.format(time_local=time_local, request_time=request_time)
            yield log_record


class LogAnalyzerDefaultConfigTest(unittest.TestCase):
    RECORDS_DATA = [(NOW, .111)] * 10

    def setUp(self):
        self.helper = TestHelper()
        self.helper.make_log_file(self.RECORDS_DATA, log_date=TOMORROW, ext='.gz')

    def tearDown(self):
        self.helper.drop_test_dirs()

    def test_make_report_for_latest_log(self):
        subprocess.run(['python3', '../log_analyzer.py'])
        self.assertTrue(os.path.isfile(self.helper.make_report_pathname(TOMORROW)))


if __name__ == '__main__':
    unittest.main()
