# Model Context Protocol (MCP) Implementation

This directory contains the implementation of the Model Context Protocol (MCP) for the API Security Scanner application. MCP provides a standardized way for LLMs to access prompt templates and other data sources, enhancing their functionality and improving integration.

## Overview

The Model Context Protocol (MCP) implementation consists of:

1. **MCP Server** (`server.js`): Implements the server-side of the protocol, providing endpoints for LLMs to discover and use tools.
2. **MCP Client** (`client.js`): Provides a client-side implementation for interacting with the MCP server.
3. **MCP Demo** (`/mcp-demo` route): A web interface for demonstrating MCP functionality.
4. **Python Integration** (`/llm/mcp_integration.py`): Python client for integrating MCP with LLM enhancement processes.
5. **Enhanced LLM Processor** (`/llm/mcp_llm_enhancer.py`): Demonstrates how to use MCP to enhance vulnerability data.

## Benefits

The MCP implementation provides several key benefits:

- **Standardized Data Access**: Provides a consistent way for LLMs to access various data sources (Redis, scan results, vulnerability databases).
- **Enhanced Prompt Management**: Allows LLMs to dynamically access and use prompt templates based on context.
- **Tool Integration**: Enables LLMs to discover and use tools within the application.
- **Reduced Technical Debt**: Eliminates custom integration code for each data source, making the codebase cleaner and more maintainable.

## Available Tools

The MCP server provides the following tools:

- **getPromptTemplate**: Get a prompt template by ID
- **listPromptTemplates**: List prompt templates by category
- **searchPromptTemplates**: Search prompt templates by keyword

## Using MCP in the Application

### JavaScript

```javascript
// Create MCP client
const mcpClient = new MCPClient('/api/mcp/mcp');

// Initialize connection
await mcpClient.initialize();

// List available tools
const tools = await mcpClient.listTools();

// Get a prompt template
const template = await mcpClient.getPromptTemplate('template_id');

// List templates by category
const scanTemplates = await mcpClient.listPromptTemplates('scan');

// Search templates
const searchResults = await mcpClient.searchPromptTemplates('security');
```

### Python

```python
from mcp_integration import MCPClient

# Create MCP client
mcp_client = MCPClient('http://localhost:3000/api/mcp/mcp')

# Initialize connection
mcp_client.initialize()

# List available tools
tools = mcp_client.list_tools()

# Get a prompt template
template = mcp_client.get_prompt_template('template_id')

# List templates by category
scan_templates = mcp_client.list_prompt_templates('scan')

# Search templates
search_results = mcp_client.search_prompt_templates('security')
```

## Integrating with LLM Enhancement

The MCP implementation can be integrated with the existing LLM enhancement process to provide more accurate and context-aware enhancements to scan results. The `mcp_llm_enhancer.py` script demonstrates this integration.

To use the MCP-enhanced LLM processor:

```bash
python llm/mcp_llm_enhancer.py --input path/to/results.json --output path/to/enhanced_results.json
```

## Demo Interface

A demo interface is available at `/mcp-demo` to demonstrate MCP functionality. This interface allows you to:

1. Initialize an MCP connection
2. List available tools
3. Browse and search prompt templates
4. Simulate LLM requests using MCP

## Future Enhancements

Potential future enhancements to the MCP implementation include:

1. **Additional Data Sources**: Integrate with more data sources, such as scan history and vulnerability databases.
2. **More Tools**: Add more tools for LLMs to use, such as running scans or generating reports.
3. **Authentication**: Add authentication to the MCP server for secure access.
4. **Versioning**: Implement versioning for the protocol to support backward compatibility.
5. **Caching**: Add caching to improve performance for frequently accessed data.

## Performance Considerations

The MCP implementation is designed to be lightweight and efficient. However, when dealing with a large number of prompt templates (as noted in the memory about 2197 templates), care should be taken to avoid performance issues. The implementation includes:

- Pagination for listing templates
- Search functionality to find specific templates
- Filtering by category to reduce the number of templates returned

These features help ensure that the MCP server remains responsive even with a large number of templates.
