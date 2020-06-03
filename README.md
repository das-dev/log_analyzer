# Log Analyzer
Script for analyzing nginx logs

### Prerequisites:
**OS:** Debian-based

**Python:** 3.7+

### How to install:
    git clone https://github.com/das-dev/log_analyzer
    
### How to use:
For run with default config:

    python3 log_analyzer.py
For run with custom config:

    python3 log_analyzer.py --config conf.json
For run with default path to custom config:

    python3 log_analyzer.py --config

Format for config file: JSON

##### Config template:
    
    {
        REPORT_SIZE: <number of urls>,
        REPORT_DIR: <path>,
        LOG_DIR: <path>,
        LOGGING_DIR: <path to logdir for own logs. Default: STDOUT >,
        ERROR_THRESHOLD: <threshold, e.g. 0.1 >
    }

### Running the tests

    python3 functional_tests.py
