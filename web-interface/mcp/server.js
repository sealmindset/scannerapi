/**
 * Model Context Protocol (MCP) Server Implementation
 * 
 * This file implements the MCP server for the API Security Scanner application,
 * providing standardized access to prompt templates and other data sources.
 */

const express = require('express');
const router = express.Router();
const redis = require('../utils/redis');

/**
 * MCP Server class that handles protocol implementation
 */
class MCPServer {
  constructor() {
    this.protocolVersion = '1.0';
    this.capabilities = {
      tools: true,
      contentTypes: ['text/plain', 'application/json']
    };
  }

  /**
   * Handle initialize request
   * @param {Object} params - Initialize parameters
   * @returns {Object} - Initialize response
   */
  async handleInitialize(params) {
    return {
      protocolVersion: this.protocolVersion,
      capabilities: this.capabilities
    };
  }

  /**
   * List available tools
   * @returns {Object} - Tools list response
   */
  async handleListTools() {
    return {
      tools: [
        {
          name: 'getPromptTemplate',
          description: 'Get a prompt template by ID',
          parameters: {
            id: {
              type: 'string',
              description: 'Prompt template ID'
            }
          }
        },
        {
          name: 'listPromptTemplates',
          description: 'List prompt templates by category',
          parameters: {
            category: {
              type: 'string',
              description: 'Category of prompts (scan, report, vulnerability, or all)'
            },
            limit: {
              type: 'number',
              description: 'Maximum number of templates to return'
            }
          }
        },
        {
          name: 'searchPromptTemplates',
          description: 'Search prompt templates by keyword',
          parameters: {
            query: {
              type: 'string',
              description: 'Search query'
            }
          }
        }
      ]
    };
  }

  /**
   * Call a tool
   * @param {Object} params - Tool call parameters
   * @returns {Object} - Tool call response
   */
  async handleCallTool(params) {
    const { toolName, arguments: args } = params;

    switch (toolName) {
      case 'getPromptTemplate':
        return await this.getPromptTemplate(args.id);
      case 'listPromptTemplates':
        return await this.listPromptTemplates(args.category, args.limit);
      case 'searchPromptTemplates':
        return await this.searchPromptTemplates(args.query);
      default:
        throw new Error(`Unknown tool: ${toolName}`);
    }
  }

  /**
   * Get a prompt template by ID
   * @param {string} id - Prompt template ID
   * @returns {Object} - Prompt template
   */
  async getPromptTemplate(id) {
    try {
      // Ensure Redis connection
      await redis.ensureConnection();
      
      const key = `prompt:${id}`;
      const promptData = await redis.getCachedReportField(id, 'template');
      
      if (!promptData) {
        return { error: 'Prompt template not found' };
      }
      
      return { template: JSON.parse(promptData) };
    } catch (error) {
      console.error('Error fetching prompt template:', error);
      return { error: 'Failed to fetch prompt template' };
    }
  }

  /**
   * List prompt templates by category
   * @param {string} category - Category of prompts
   * @param {number} limit - Maximum number of templates to return
   * @returns {Object} - List of prompt templates
   */
  async listPromptTemplates(category = 'all', limit = 20) {
    try {
      // Ensure Redis connection
      await redis.ensureConnection();
      
      // Get all scan IDs as a proxy for prompt templates
      // This is a simplified approach to avoid performance issues with large numbers of templates
      const scanIds = await redis.getAllScanIds(limit, 0);
      
      const templates = [];
      for (const scanId of scanIds) {
        // Get metadata for the scan
        const metadata = await redis.getScanMetadata(scanId);
        if (metadata) {
          // Check if this scan has a prompt template
          const promptData = await redis.getCachedReportField(scanId, 'template');
          if (promptData) {
            try {
              const template = JSON.parse(promptData);
              // Filter by category if specified
              if (category === 'all' || template.category === category) {
                templates.push({
                  id: scanId,
                  ...template
                });
              }
            } catch (e) {
              console.error(`Error parsing template for scan ${scanId}:`, e);
            }
          }
        }
        
        // Stop if we've reached the limit
        if (templates.length >= limit) {
          break;
        }
      }
      
      return { templates, total: templates.length };
    } catch (error) {
      console.error('Error listing prompt templates:', error);
      return { error: 'Failed to list prompt templates' };
    }
  }

  /**
   * Search prompt templates by keyword
   * @param {string} query - Search query
   * @returns {Object} - Search results
   */
  async searchPromptTemplates(query) {
    try {
      if (!query || query.trim() === '') {
        return { error: 'Search query is required' };
      }
      
      // Ensure Redis connection
      await redis.ensureConnection();
      
      // Get a limited number of scan IDs to search through
      // This is a performance optimization to avoid searching through all templates
      const scanIds = await redis.getAllScanIds(100, 0);
      const results = [];
      const searchTerm = query.toLowerCase();
      
      // Only search through a limited number of templates to avoid performance issues
      for (const scanId of scanIds) {
        // Get metadata for the scan
        const metadata = await redis.getScanMetadata(scanId);
        if (metadata) {
          // First check if the metadata contains the search term
          const metadataText = [
            metadata.title || '',
            metadata.description || ''
          ].join(' ').toLowerCase();
          
          if (metadataText.includes(searchTerm)) {
            // If metadata matches, check for a template
            const promptData = await redis.getCachedReportField(scanId, 'template');
            if (promptData) {
              try {
                const template = JSON.parse(promptData);
                results.push({
                  id: scanId,
                  ...template
                });
              } catch (e) {
                console.error(`Error parsing template for scan ${scanId}:`, e);
              }
            }
            continue;
          }
          
          // If metadata doesn't match, check the template content
          const promptData = await redis.getCachedReportField(scanId, 'template');
          if (promptData) {
            try {
              const template = JSON.parse(promptData);
              
              // Search in name, description, and template content
              const searchableText = [
                template.name || '',
                template.description || '',
                template.template || ''
              ].join(' ').toLowerCase();
              
              if (searchableText.includes(searchTerm)) {
                results.push({
                  id: scanId,
                  ...template
                });
              }
            } catch (e) {
              console.error(`Error parsing template for scan ${scanId}:`, e);
            }
          }
        }
        
        // Limit results to 20 for performance
        if (results.length >= 20) {
          break;
        }
      }
      
      return { results, count: results.length };
    } catch (error) {
      console.error('Error searching prompt templates:', error);
      return { error: 'Failed to search prompt templates' };
    }
  }

  /**
   * Process an MCP request
   * @param {Object} request - MCP request
   * @returns {Object} - MCP response
   */
  async processRequest(request) {
    const { id, method, params } = request;
    
    try {
      let result;
      
      switch (method) {
        case 'initialize':
          result = await this.handleInitialize(params);
          break;
        case 'listTools':
          result = await this.handleListTools();
          break;
        case 'callTool':
          result = await this.handleCallTool(params);
          break;
        default:
          throw new Error(`Unknown method: ${method}`);
      }
      
      return {
        jsonrpc: '2.0',
        id,
        result
      };
    } catch (error) {
      console.error('MCP error:', error);
      return {
        jsonrpc: '2.0',
        id,
        error: {
          code: -32603,
          message: error.message || 'Internal error'
        }
      };
    }
  }
}

// Create MCP server instance
const mcpServer = new MCPServer();

// MCP endpoint
router.post('/mcp', express.json(), async (req, res) => {
  try {
    const mcpRequest = req.body;
    
    // Validate request format
    if (!mcpRequest.jsonrpc || mcpRequest.jsonrpc !== '2.0' || !mcpRequest.method) {
      return res.status(400).json({
        jsonrpc: '2.0',
        id: mcpRequest.id,
        error: {
          code: -32600,
          message: 'Invalid request'
        }
      });
    }
    
    const response = await mcpServer.processRequest(mcpRequest);
    res.json(response);
  } catch (error) {
    console.error('Error processing MCP request:', error);
    res.status(500).json({
      jsonrpc: '2.0',
      id: req.body.id,
      error: {
        code: -32603,
        message: 'Internal server error'
      }
    });
  }
});

module.exports = router;
