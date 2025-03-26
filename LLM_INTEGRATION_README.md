# LLM-Enhanced Vulnerability Report Generation

This document explains how to use the enhanced vulnerability reporting system that integrates LLM capabilities for improved remediation suggestions and vulnerability descriptions.

## Overview

The integration combines three key components:

1. **Report Generator** (`report_generator.py`) - Creates structured reports from scan results
2. **LLM Remediation Middleware** (`llm_remediation_middleware.py`) - Enhances remediation suggestions
3. **LLM Description Middleware** (`llm_description.py`) - Enhances vulnerability descriptions

## New Command: `enhance-with-llm`

A new command has been added to `report_generator.py` that provides a complete pipeline for enhancing scan results with LLM-generated content:

```bash
python report_generator.py enhance-with-llm --input <scan_results.json> --output <enhanced_results.json>
```

### Options

- `--input` - Path to the input scan results file (required)
- `--output` - Path to save the enhanced results (required)
- `--remediation` - Enable remediation enhancement (default: true)
- `--description` - Enable description enhancement (default: true)
- `--provider` - LLM provider to use: 'openai' or 'ollama' (default: openai)
- `--model` - Model to use (provider-specific)
- `--batch-size` - Batch size for processing (default: 5)
- `--max-workers` - Maximum number of worker threads (default: 3)
- `--generate-report` - Generate a report after enhancement
- `--report-format` - Format of the report: json, csv, html (default: html)
- `--report-output` - Path to save the report (defaults to ./reports/report_<scanid>.<format>)

## Complete Workflow Example

### 1. Run a scan and get results

```bash
# Assuming you have a scan results file named scan_123.json
```

### 2. Enhance the results with LLM and generate a report

```bash
python report_generator.py enhance-with-llm \
  --input scan_123.json \
  --output enhanced_scan_123.json \
  --provider openai \
  --model gpt-4o \
  --generate-report \
  --report-format html
```

This will:
1. Enhance remediation details using LLM
2. Enhance vulnerability descriptions using LLM
3. Generate an HTML report from the enhanced results

### 3. Using Ollama instead of OpenAI

```bash
python report_generator.py enhance-with-llm \
  --input scan_123.json \
  --output enhanced_scan_123.json \
  --provider ollama \
  --model llama3 \
  --generate-report \
  --report-format html
```

## Using Components Separately

You can still use each component separately:

### LLM Remediation Middleware

```bash
python llm_remediation_middleware.py --input scan_123.json --output remediation_enhanced.json
```

### LLM Description Middleware

```bash
python llm_description.py --input scan_123.json --output description_enhanced.json
```

### Report Generator

```bash
python report_generator.py generate --scanid 123 --format html --output report.html
```

## Special Handling for Rate-Limited Account Creation

The system has been enhanced to handle the "Rate-Limited Account Creation" vulnerability with special care, including:

1. Detailed metrics tracking of successful account creation rates
2. Evidence of testing at different rates
3. Information about the optimal delay between requests
4. Specific rate at which account creation can occur despite rate limiting

## API Structure Detection

The middleware components are designed to adapt to different API structures, including:

- Standard RESTful APIs
- Custom endpoint structures (e.g., `/auth/sign-up` instead of `/users`)
- Different field naming conventions

This makes the scanner more versatile in detecting vulnerabilities regardless of endpoint paths.

## Environment Variables

- `OPENAI_API_KEY` - Required when using OpenAI as the LLM provider
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD` - Optional Redis configuration for caching

## Troubleshooting

If you encounter issues with the LLM enhancement:

1. Check that the required environment variables are set
2. Verify that Redis is running if you're using caching
3. For Ollama, ensure the service is running at the specified URL
4. Check the log output for specific error messages
