# LLM Remediation Middleware

This middleware enhances vulnerability remediation details in scan results using LLM APIs (OpenAI or Ollama) with Redis caching. It integrates seamlessly with the existing vulnerability report generation workflow.

## Features

- **Enhanced Remediation**: Automatically generates detailed, actionable remediation steps for each vulnerability
- **Multiple LLM Support**: Works with both OpenAI and Ollama APIs
- **Redis Caching**: Caches LLM responses to reduce API costs and improve performance
- **Pydantic Validation**: Uses Pydantic models to validate and structure input/output data
- **Flexible Configuration**: Configurable via environment variables, config files, or command-line arguments

## Installation

1. Install the required dependencies:

```bash
pip install -r llm_middleware_requirements.txt
```

2. Set up Redis (if not already running):

```bash
# Using Docker
docker run --name redis -p 6379:6379 -d redis

# Or install Redis directly on your system
# macOS: brew install redis
# Ubuntu: sudo apt install redis-server
```

3. Create a `.env` file based on the provided `.env.example`:

```bash
cp .env.example .env
# Edit .env with your configuration
```

## Usage

### Basic Usage

```bash
python llm_remediation_middleware.py --input results/20250316111953.json --output results/enhanced_20250316111953.json
```

### Integration with Report Generator

After enhancing the scan results, you can generate a report using the existing report generator:

```bash
# First, enhance the scan results with LLM remediation
python llm_remediation_middleware.py --input results/20250316111953.json --output results/enhanced_20250316111953.json

# Then, generate a report using the enhanced results
python report_generator.py quick-report enhanced_20250316111953 --format html --output reports/enhanced_report.html
```

### Configuration Options

#### Environment Variables

All configuration options can be set via environment variables with the `LLM_` prefix:

- `LLM_PROVIDER`: LLM provider to use (`openai` or `ollama`)
- `LLM_OPENAI_API_KEY`: OpenAI API key (required when using OpenAI)
- `LLM_OLLAMA_BASE_URL`: Ollama API base URL (default: `http://localhost:11434`)
- `LLM_OLLAMA_MODEL`: Ollama model to use (default: `llama3`)
- `LLM_REDIS_HOST`: Redis server host (default: `localhost`)
- `LLM_REDIS_PORT`: Redis server port (default: `6379`)
- `LLM_REDIS_DB`: Redis database number (default: `0`)
- `LLM_REDIS_PASSWORD`: Redis server password (optional)
- `LLM_REDIS_CACHE_TTL`: Time-to-live for cached remediation in seconds (default: 7 days)
- `LLM_TEMPERATURE`: Temperature for LLM generation (default: `0.2`)
- `LLM_MAX_TOKENS`: Maximum tokens for LLM generation (default: `1000`)

#### Command-Line Arguments

- `--input`: Path to input scan results JSON file (required)
- `--output`: Path to output enhanced scan results JSON file (required)
- `--config`: Path to configuration JSON file (optional)
- `--llm-provider`: LLM provider to use (`openai` or `ollama`)

#### Configuration File

You can also provide a JSON configuration file with the `--config` option:

```json
{
  "llm_provider": "openai",
  "openai_api_key": "your_api_key_here",
  "temperature": 0.3,
  "max_tokens": 1500
}
```

## How It Works

1. **Load and Validate Input**: The middleware reads scan results from a JSON file and validates the data structure using Pydantic models.

2. **Process Vulnerabilities**: For each vulnerability in the scan results, the middleware:
   - Generates a unique cache key based on the vulnerability details
   - Checks if a cached remediation exists in Redis
   - If cached, uses the cached remediation
   - If not cached, generates a new remediation using the LLM API and caches it

3. **LLM Integration**: The middleware uses LangChain to interact with the LLM API:
   - Creates a prompt template that includes vulnerability details
   - Sends the prompt to the LLM API
   - Processes the response and extracts the remediation

4. **Update Scan Results**: The middleware updates the scan results with the enhanced remediation details.

5. **Save Enhanced Results**: The enhanced scan results are saved to a new JSON file, which can be used with the existing report generator.

## Customizing Prompts

The prompt template can be customized in the `_setup_prompt_template` method of the `LLMRemediationMiddleware` class. The default prompt is designed to generate comprehensive remediation steps for API security vulnerabilities.

## Error Handling

The middleware includes robust error handling to ensure that failures in LLM API calls or Redis operations don't disrupt the overall workflow. If Redis is unavailable, the middleware will continue without caching. If an LLM API call fails, the middleware will log the error and continue with the next vulnerability.

## Development

### Adding Support for New LLM Providers

To add support for a new LLM provider, update the `_setup_llm` method in the `LLMRemediationMiddleware` class and add the necessary configuration options to the `RemediationConfig` class.

### Extending Vulnerability Models

The Pydantic models can be extended to support additional vulnerability data structures. Update the `Vulnerability`, `ScannerResults`, and `ScanResults` classes as needed.

## License

This project is licensed under the same license as the main scanner project.
