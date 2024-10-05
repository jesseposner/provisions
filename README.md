# Provisions Protocol Implementation

[![Build Status](https://github.com/jesseposner/provisions/actions/workflows/ci.yml/badge.svg)](https://github.com/jesseposner/provisions/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Versions](https://img.shields.io/pypi/pyversions/provisions.svg)](https://pypi.org/project/provisions/)

A Python implementation of the Provisions protocol, featuring elliptic curve cryptography primitives for the secp256k1 curve.

## Features

- Elliptic curve point arithmetic on secp256k1.
- Point serialization and deserialization in SEC1 format.
- Comprehensive test suite using pytest and Hypothesis.

## Installation

Clone the repository and install the package:

```bash
git clone https://github.com/jesseposner/provisions.git
cd provisions
pip install -e .
```

To install development dependencies:

```bash
pip install -e .[dev]
```
## Testing

Run the test suite using pytest:

```bash
pytest
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```
