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

### Running the tests

    python3 functional_tests.py