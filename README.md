# Hierarchical-blockchain

A hierarchical blockchain framework inspired by Hyperledger Fabric architecture, designed for enterprise applications with a focus on business operations rather than cryptocurrency.

## Installation

```bash
pip install -r requirements.txt
```

---

## Running Demos

Run the main framework demonstration:

```bash
python demo.py
```

Run the key backup and recovery demonstration:

```bash
python demo_key_backup.py
```

---

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

---

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

---

## Automated Risk Management Tests

To run automated risk management tests:

```bash
python testing/automated_tests.py
```

To run with verbose output:

```bash
python testing/automated_tests.py -v
```

---

## Recovery Tests

To run automated recovery tests:

```bash
python testing/recovery_tests.py
```

---

## Validation Suites

To run priority-based validation tests:

```bash
python testing/validation_suites.py
```