# Hierarchical-blockchian

## Installation

```bash
pip install -r requirements.txt
```

## Running Tests

To run all unit tests:

```bash
python -m pytest tests/unit -v
```

To run all integration tests:

```bash
python -m pytest tests/integration -v
```

To run all tests:

```bash
python -m pytest tests -v
```

## Static Analysis

To run static code analysis:

```bash
python testing/static_analysis.py
```

To run static code analysis with text output:

```bash
python testing/static_analysis.py --format text
```

To run static code analysis and save results to a file:

```bash
python testing/static_analysis.py --output analysis_report.json
python testing/static_analysis.py --format text --output analysis_report.txt
```

## Automated Risk Management Tests

To run automated risk management tests:

```bash
python testing/automated_tests.py
```

To run with verbose output:

```bash
python testing/automated_tests.py -v
```