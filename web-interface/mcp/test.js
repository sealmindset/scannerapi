/**
 * MCP Integration Test
 * 
 * This file provides simple tests for the MCP implementation.
 */

const MCPServer = require('./server');
const fetch = require('node-fetch');
const { promisify } = require('util');
const redis = require('../redis-client');

// Promisify Redis methods
const redisSet = promisify(redis.set).bind(redis);

// Test data
const testPrompts = [
  {
    id: 'test:scan:1',
    name: 'API Scan Basic',
    description: 'Basic scan prompt for API security assessment',
    category: 'scan',
    template: 'Analyze the security of this API endpoint: {{endpoint}}. Look for common vulnerabilities.'
  },
  {
    id: 'test:report:1',
    name: 'Security Report Summary',
    description: 'Summarizes security findings in a concise report',
    category: 'report',
    template: 'Based on the scan results, here is a summary of security issues found: {{findings}}'
  }
];

/**
 * Setup test data in Redis
 */
async function setupTestData() {
  console.log('Setting up test data in Redis...');
  
  for (const prompt of testPrompts) {
    const key = `prompt:${prompt.id}`;
    await redisSet(key, JSON.stringify(prompt));
    console.log(`Added test prompt: ${key}`);
  }
  
  console.log('Test data setup complete.');
}

/**
 * Run MCP tests
 */
async function runTests() {
  console.log('Starting MCP tests...');
  
  try {
    // Setup test data
    await setupTestData();
    
    // Test initialization
    console.log('\nTest 1: Initialize MCP connection');
    const initResult = await sendMCPRequest('initialize', {
      protocolVersion: '1.0'
    });
    console.log('Initialization result:', JSON.stringify(initResult, null, 2));
    
    // Test listing tools
    console.log('\nTest 2: List available tools');
    const toolsResult = await sendMCPRequest('listTools', {});
    console.log('Tools result:', JSON.stringify(toolsResult, null, 2));
    
    // Test getting a prompt template
    console.log('\nTest 3: Get prompt template');
    const promptResult = await sendMCPRequest('callTool', {
      toolName: 'getPromptTemplate',
      arguments: {
        id: 'test:scan:1'
      }
    });
    console.log('Prompt template result:', JSON.stringify(promptResult, null, 2));
    
    // Test listing prompt templates
    console.log('\nTest 4: List prompt templates');
    const listResult = await sendMCPRequest('callTool', {
      toolName: 'listPromptTemplates',
      arguments: {
        category: 'all',
        limit: 10
      }
    });
    console.log('List templates result:', JSON.stringify(listResult, null, 2));
    
    // Test searching prompt templates
    console.log('\nTest 5: Search prompt templates');
    const searchResult = await sendMCPRequest('callTool', {
      toolName: 'searchPromptTemplates',
      arguments: {
        query: 'security'
      }
    });
    console.log('Search result:', JSON.stringify(searchResult, null, 2));
    
    console.log('\nAll tests completed successfully!');
  } catch (error) {
    console.error('Test failed:', error);
  }
}

/**
 * Send an MCP request to the server
 * @param {string} method - Method name
 * @param {Object} params - Method parameters
 * @returns {Promise<Object>} - Response from server
 */
async function sendMCPRequest(method, params) {
  const request = {
    jsonrpc: '2.0',
    id: Date.now(),
    method,
    params
  };
  
  try {
    // For testing purposes, we're directly calling the server
    // In a real scenario, this would be an HTTP request
    const mcpServer = new MCPServer();
    const response = await mcpServer.processRequest(request);
    
    if (response.error) {
      throw new Error(`MCP error: ${response.error.message}`);
    }
    
    return response.result;
  } catch (error) {
    console.error('MCP request error:', error);
    throw error;
  }
}

// Run the tests
if (require.main === module) {
  runTests().catch(console.error);
}

module.exports = { runTests };
