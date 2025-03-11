# API Security Scanner

A comprehensive Python-based backend API security scanner that performs real-world tests for various vulnerabilities.

## Features

- **Modular Vulnerability Detection**: Individual scanner modules for different vulnerability types
- **Orchestration Master**: Coordinates the execution of scanner modules (sequential or concurrent)
- **Advanced Logging System**: Comprehensive logging with multiple levels
- **Scan Configuration**: YAML/JSON-based configuration
- **API Fuzzing**: Intelligent fuzzing mechanisms for API parameters
- **Business Logic Vulnerability Detection**: Detects business logic flaws

## Vulnerability Detection Modules

- Unrestricted Account Creation
- Mass Assignment
- Unauthorized Password Change
- Broken Object Level Authorization
- Excessive Data Exposure through debug endpoint
- User and Password Enumeration
- RegexDOS (Denial of Service)
- Lack of Resources & Rate Limiting
- JWT Authentication Bypass via Weak Signing Key
- SQLi Injection

## Installation

```bash
pip install -r requirements.txt
```

## Usage

1. Create a configuration file (YAML or JSON) defining scan parameters
2. Run the scanner using the master orchestration script:

```bash
python scanner.py --config config.yaml
```

## Configuration Example

```yaml
target:
  base_url: "https://api.example.com"
  auth:
    type: "bearer"
    token: "your-auth-token"

scanners:
  - name: "unrestricted_account_creation"
    enabled: true
    concurrent: false
    config:
      endpoint: "/api/users"
      method: "POST"
  
  # Additional scanner configurations...

logging:
  level: "INFO"
  output: "logs/scan.log"
  format: "json"
```

## Output

The scanner provides a detailed summary of detected vulnerabilities, including:
- Which tests were performed
- Results of each test
- Detailed logs for further analysis
