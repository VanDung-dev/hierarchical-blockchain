# Hierarchical-blockchain

A hierarchical blockchain framework inspired by Hyperledger Fabric architecture, designed for enterprise applications with a focus on business operations rather than cryptocurrency.

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

## Installation

### Install from source

```bash
pip install .
```

### Install in development mode

```bash
pip install -e .
```

### Install from PyPI (when available)

```bash
pip install hierarchical-blockchain
```

## Running server

```bash
python -m hierarchical_blockchain.api.server
```

## Using the package

After installation, you can import components from the package:

```python
from hierarchical_blockchain.core.block import Block
from hierarchical_blockchain.core.blockchain import Blockchain
```

## Running Demos

- Run the main framework demonstration:
    ```bash
    python demo/demo.py
    ```

- Run the key backup and recovery demonstration:
    ```bash
    python demo/demo_key_backup.py
    ```

- Run the API demo:
    ```bash
    python demo/demo_api.py
    ```

## Running Tests

- To run all unit tests:
    ```bash
    python -m pytest tests/unit -v
    ```

- To run all integration tests:
    ```bash
    python -m pytest tests/integration -v
    ```

- To run all tests:
    ```bash
    python -m pytest tests -v
    ```

## Static Analysis

- To run static code analysis:
    ```bash
    python -m hierarchical_blockchain.testing.static_analysis
    ```

- To run static code analysis with text output:
    ```bash
    python -m hierarchical_blockchain.testing.static_analysis --format text
    ```

- To run static code analysis and save results to a file:
    ```bash
    python -m hierarchical_blockchain.testing.static_analysis --output analysis_report.json
    python -m hierarchical_blockchain.testing.static_analysis --format text --output analysis_report.txt
    ```

## Automated Tests

- To run automated risk management tests:
    ```bash
    python -m hierarchical_blockchain.testing.automated_tests
    ```

  - To run with verbose output:
      ```bash
      python -m hierarchical_blockchain.testing.automated_tests -v
      ```

- To run automated recovery tests:
    ```bash
    python -m hierarchical_blockchain.testing.recovery_tests
    ```

- To run priority-based validation tests:
    ```bash
    python -m hierarchical_blockchain.testing.validation_suites
    ```