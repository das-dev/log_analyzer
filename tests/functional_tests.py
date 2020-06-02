# -*- coding: utf-8 -*-
import os
import gzip
import unittest
import datetime
import random
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

    def make_log_file(self, date=NOW, ext='', lines_number=10):
        try:
            os.mkdir(self.config['LOG_DIR'])
        except FileExistsError:
            pass

        basename = LOG_FILENAME_TEMPLATE.format(date=date.strftime('%Y%m%d'))
        pathname = os.path.join(self.config['LOG_DIR'], f'{basename}{ext}')
        lines = self._generate_log_records(lines_number)
        reader = gzip.open if ext == '.gz' else open
        with reader(pathname, 'wb') as fl:
            fl.write('\n'.join(lines).encode())
        return pathname

    def _generate_log_records(self, lines_number):
        request_time = 0.111
        time_local = NOW.strftime('%d/%b/%Y:%H:%M:%S %z')
        for _ in range(lines_number):
            log_record = LOG_RECORD_TEMPLATE.format(time_local=time_local, request_time=request_time)
            print(log_record)
            yield log_record


class LogAnalyzerDefaultConfigTest(unittest.TestCase):
    def setUp(self):
        helper = TestHelper()
        log_file = helper.make_log_file(date=TOMORROW, ext='.gz')

    def tearDown(self):
        pass

    def test_make_report_for_latest_log(self):
        subprocess.run(['python3', '../log_analyzer.py'])


if __name__ == '__main__':
    unittest.main()
