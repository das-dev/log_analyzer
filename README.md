# Log Analyzer
Script for analyzing nginx logs

### Prerequisites:
**OS:** Debian-based

**Python:** 3.7+

### How to install:
    git clone https://github.com/das-dev/log_analyzer
    
### How to use:
Run with default config:

    python3 log_analyzer.py
Run with custom config:

    python3 log_analyzer.py --config conf.json
Run with default path to custom config:

    python3 log_analyzer.py --config

Config file format: JSON
Default path to config: /usr/local/etc/config.json

#### Config template:
    
    {
        REPORT_SIZE: <number of urls (integer)>,
        REPORT_DIR: <path (string)>,
        LOG_DIR: <path (string)>,
        LOGGING_FILE: <path (string) to logfile for own logging. Default: STDOUT>,
        ERROR_THRESHOLD: <errors rate, e.g. 0.1 (float)>
    }

### Running the tests

    python3 functional_tests.py
