/**
 * Model Context Protocol (MCP) Client Implementation
 * 
 * This file implements the MCP client for the API Security Scanner application,
 * providing a standardized way for LLMs to interact with prompt templates and other data.
 */

class MCPClient {
  /**
   * Create a new MCP client
   * @param {string} endpoint - MCP server endpoint
   */
  constructor(endpoint) {
    this.endpoint = endpoint;
    this.initialized = false;
    this.requestId = 1;
    this.capabilities = null;
  }

  /**
   * Generate a new request ID
   * @returns {number} - Request ID
   */
  getNextRequestId() {
    return this.requestId++;
  }

  /**
   * Send a request to the MCP server
   * @param {string} method - Method name
   * @param {Object} params - Method parameters
   * @returns {Promise<Object>} - Response from server
   */
  async sendRequest(method, params = {}) {
    const request = {
      jsonrpc: '2.0',
      id: this.getNextRequestId(),
      method,
      params
    };

    try {
      const response = await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(request)
      });

      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }

      const data = await response.json();
      
      if (data.error) {
        throw new Error(`MCP error: ${data.error.message}`);
      }
      
      return data.result;
    } catch (error) {
      console.error('MCP client error:', error);
      throw error;
    }
  }

  /**
   * Initialize the MCP connection
   * @returns {Promise<Object>} - Initialization result
   */
  async initialize() {
    if (this.initialized) {
      return this.capabilities;
    }

    try {
      const result = await this.sendRequest('initialize', {
        protocolVersion: '1.0'
      });
      
      this.capabilities = result.capabilities;
      this.initialized = true;
      return result;
    } catch (error) {
      console.error('Failed to initialize MCP connection:', error);
      throw error;
    }
  }

  /**
   * Get the list of available tools
   * @returns {Promise<Object>} - Tools list
   */
  async listTools() {
    if (!this.initialized) {
      await this.initialize();
    }
    
    return this.sendRequest('listTools');
  }

  /**
   * Call a tool
   * @param {string} toolName - Name of the tool to call
   * @param {Object} args - Tool arguments
   * @returns {Promise<Object>} - Tool result
   */
  async callTool(toolName, args = {}) {
    if (!this.initialized) {
      await this.initialize();
    }
    
    return this.sendRequest('callTool', {
      toolName,
      arguments: args
    });
  }

  /**
   * Get a prompt template by ID
   * @param {string} id - Prompt template ID
   * @returns {Promise<Object>} - Prompt template
   */
  async getPromptTemplate(id) {
    return this.callTool('getPromptTemplate', { id });
  }

  /**
   * List prompt templates by category
   * @param {string} category - Category of prompts
   * @param {number} limit - Maximum number of templates to return
   * @returns {Promise<Object>} - List of prompt templates
   */
  async listPromptTemplates(category = 'all', limit = 20) {
    return this.callTool('listPromptTemplates', { category, limit });
  }

  /**
   * Search prompt templates by keyword
   * @param {string} query - Search query
   * @returns {Promise<Object>} - Search results
   */
  async searchPromptTemplates(query) {
    return this.callTool('searchPromptTemplates', { query });
  }
}

// Export the client for use in browser or Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = MCPClient;
} else {
  // For browser use
  window.MCPClient = MCPClient;
}
