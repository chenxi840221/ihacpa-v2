# Test Data Directory

This directory contains test data files and sample inputs for IHACPA v2.0 testing.

## Files

- `2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx` - Real Python package inventory (486 packages)
- `sample_packages.json` - Curated test packages
- `test_vulnerabilities.json` - Mock vulnerability data
- `config_test.yaml` - Test configuration files

## Data Privacy

- Real package data is included for testing purposes
- No sensitive information is stored in this directory
- Excel files contain publicly available package information
- Test results are gitignored to prevent data accumulation

## Usage

Test scripts automatically look for data files in this directory. The main Excel file serves as the primary test dataset for validating IHACPA v2.0 against real-world package inventories.