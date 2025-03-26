/**
 * Script to fix the report editor by processing enhanced results and storing them in Redis
 * 
 * Usage: node fix-report-editor.js <scanId> <enhancedResultsFilePath>
 */

const fs = require('fs');
const path = require('path');
const redis = require('redis');
require('dotenv').config();

// Get Redis configuration from environment variables
const redisHost = process.env.LLM_REDIS_HOST || 'localhost';
const redisPort = process.env.LLM_REDIS_PORT || 6379;
const redisDb = process.env.LLM_REDIS_DB || 0;
const redisPassword = process.env.LLM_REDIS_PASSWORD || '';

// Create Redis client
let redisUrl = `redis://${redisHost}:${redisPort}/${redisDb}`;
if (redisPassword) {
  redisUrl = `redis://:${redisPassword}@${redisHost}:${redisPort}/${redisDb}`;
}

const client = redis.createClient({
  url: redisUrl
});

// Get command line arguments
const scanId = process.argv[2];
const enhancedFilePath = process.argv[3];

if (!scanId) {
  console.error('Usage: node fix-report-editor.js <scanId> <enhancedResultsFilePath>');
  console.error('If enhancedResultsFilePath is not provided, the script will try to generate sample data');
  process.exit(1);
}

// Function to cache report field in Redis
async function cacheReportField(scanId, field, content, expiry = 86400) {
  try {
    // Create key in format report:scanId:field
    const key = `report:${scanId}:${field}`;
    
    // Store in Redis with expiry
    await client.set(key, content);
    await client.expire(key, expiry);
    
    return true;
  } catch (error) {
    console.error(`Error caching report field: ${error.message}`);
    return false;
  }
}

// Function to process enhanced results file and store in Redis
async function processEnhancedResults(scanId, enhancedFilePath) {
  try {
    console.log(`Processing enhanced results from ${enhancedFilePath}`);
    
    // Read the enhanced content
    const enhancedContent = JSON.parse(fs.readFileSync(enhancedFilePath, 'utf8'));
    console.log(`Read enhanced content with ${Object.keys(enhancedContent.scanners || {}).length} scanners`);
    
    // Store vulnerabilities in Redis
    let vulnCount = 0;
    const scanners = enhancedContent.scanners || {};
    
    for (const scanner of Object.keys(scanners)) {
      if (scanners[scanner].vulnerabilities) {
        const vulns = scanners[scanner].vulnerabilities;
        console.log(`Processing ${vulns.length} vulnerabilities from scanner ${scanner}`);
        
        for (const vuln of vulns) {
          const vulnId = `${scanner}:${vuln.id || vuln.title.replace(/\\s+/g, '_').toLowerCase()}`;
          console.log(`Processing vulnerability ${vulnId}`);
          
          // Cache each field separately
          await cacheReportField(scanId, `vuln:${vulnId}:title`, vuln.title);
          await cacheReportField(scanId, `vuln:${vulnId}:severity`, vuln.severity);
          await cacheReportField(scanId, `vuln:${vulnId}:description`, vuln.description || '');
          await cacheReportField(scanId, `vuln:${vulnId}:remediation`, vuln.remediation || '');
          
          if (vuln.details) {
            await cacheReportField(scanId, `vuln:${vulnId}:details`, JSON.stringify(vuln.details));
          }
          
          if (vuln.evidence) {
            await cacheReportField(scanId, `vuln:${vulnId}:evidence`, JSON.stringify(vuln.evidence));
          }
          
          vulnCount++;
        }
      }
    }
    
    // Store scan metadata
    await cacheReportField(scanId, 'metadata', JSON.stringify({
      scanId,
      timestamp: enhancedContent.timestamp || new Date().toISOString(),
      target: enhancedContent.target || 'Unknown',
      summary: enhancedContent.summary || 'Scan results',
      title: enhancedContent.title || enhancedContent.scan_info?.title || `Scan ${scanId}`
    }));
    
    // Store vulnerability list
    const vulnList = [];
    for (const scanner of Object.keys(scanners)) {
      if (scanners[scanner].vulnerabilities) {
        for (const vuln of scanners[scanner].vulnerabilities) {
          vulnList.push({
            id: `${scanner}:${vuln.id || vuln.title.replace(/\\s+/g, '_').toLowerCase()}`,
            title: vuln.title,
            severity: vuln.severity,
            scanner
          });
        }
      }
    }
    
    await cacheReportField(scanId, 'vulnList', JSON.stringify(vulnList));
    
    console.log(`Successfully processed ${vulnCount} vulnerabilities and stored in Redis`);
    console.log(`Vulnerability list contains ${vulnList.length} items`);
    
    return { success: true, message: `Enhanced content processed and stored for scan ${scanId}` };
  } catch (error) {
    console.error(`Error processing enhanced results: ${error.message}`);
    return { success: false, message: `Error: ${error.message}` };
  }
}

// Function to generate sample data if no enhanced file is provided
async function generateSampleData(scanId) {
  try {
    console.log(`Generating sample data for scan ${scanId}`);
    
    // Create sample vulnerabilities
    const sampleVulns = [
      {
        id: 'sample:vuln1',
        title: 'Excessive Data Exposure in Debug Endpoint',
        severity: 'high',
        description: 'The API exposes sensitive data through a debug endpoint that is accessible without proper authentication.',
        remediation: 'Remove debug endpoints from production or implement proper authentication and authorization controls.',
        scanner: 'sample',
        details: {
          endpoint: '/api/debug',
          method: 'GET',
          impact: 'Attackers can access sensitive information without authorization.'
        },
        evidence: {
          request: 'GET /api/debug HTTP/1.1\nHost: example.com',
          response: '200 OK\n{"debug": true, "users": [{"id": 1, "username": "admin", "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99"}]}'
        }
      },
      {
        id: 'sample:vuln2',
        title: 'Insecure Direct Object Reference',
        severity: 'medium',
        description: 'The API allows users to access resources by manipulating the resource identifier, without proper authorization checks.',
        remediation: 'Implement proper authorization checks for all resource access. Use indirect references that are mapped to actual resource identifiers on the server.',
        scanner: 'sample',
        details: {
          endpoint: '/api/users/{id}',
          method: 'GET',
          impact: 'Attackers can access unauthorized resources by manipulating the resource identifier.'
        },
        evidence: {
          request: 'GET /api/users/2 HTTP/1.1\nHost: example.com\nAuthorization: Bearer user1_token',
          response: '200 OK\n{"id": 2, "username": "user2", "email": "user2@example.com", "role": "admin"}'
        }
      },
      {
        id: 'sample:vuln3',
        title: 'Missing Rate Limiting',
        severity: 'low',
        description: 'The API does not implement rate limiting, allowing attackers to perform brute force attacks or cause denial of service.',
        remediation: 'Implement rate limiting for all API endpoints, especially authentication endpoints.',
        scanner: 'sample',
        details: {
          endpoint: '/api/login',
          method: 'POST',
          impact: 'Attackers can perform brute force attacks against authentication endpoints.'
        },
        evidence: {
          request: 'POST /api/login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{"username": "admin", "password": "password"}',
          response: '401 Unauthorized\n{"error": "Invalid credentials"}'
        }
      }
    ];
    
    // Store vulnerabilities in Redis
    for (const vuln of sampleVulns) {
      await cacheReportField(scanId, `vuln:${vuln.id}:title`, vuln.title);
      await cacheReportField(scanId, `vuln:${vuln.id}:severity`, vuln.severity);
      await cacheReportField(scanId, `vuln:${vuln.id}:description`, vuln.description);
      await cacheReportField(scanId, `vuln:${vuln.id}:remediation`, vuln.remediation);
      
      if (vuln.details) {
        await cacheReportField(scanId, `vuln:${vuln.id}:details`, JSON.stringify(vuln.details));
      }
      
      if (vuln.evidence) {
        await cacheReportField(scanId, `vuln:${vuln.id}:evidence`, JSON.stringify(vuln.evidence));
      }
    }
    
    // Store scan metadata
    await cacheReportField(scanId, 'metadata', JSON.stringify({
      scanId,
      timestamp: new Date().toISOString(),
      target: 'example.com',
      summary: 'Sample scan results for demonstration',
      title: `Sample Scan ${scanId}`
    }));
    
    // Store vulnerability list
    const vulnList = sampleVulns.map(vuln => ({
      id: vuln.id,
      title: vuln.title,
      severity: vuln.severity,
      scanner: vuln.scanner
    }));
    
    await cacheReportField(scanId, 'vulnList', JSON.stringify(vulnList));
    
    console.log(`Successfully generated sample data with ${sampleVulns.length} vulnerabilities and stored in Redis`);
    
    return { success: true, message: `Sample data generated and stored for scan ${scanId}` };
  } catch (error) {
    console.error(`Error generating sample data: ${error.message}`);
    return { success: false, message: `Error: ${error.message}` };
  }
}

// Main function
async function main() {
  try {
    // Connect to Redis
    await client.connect();
    console.log('Connected to Redis');
    
    let result;
    
    if (enhancedFilePath && fs.existsSync(enhancedFilePath)) {
      // Process enhanced results file
      result = await processEnhancedResults(scanId, enhancedFilePath);
    } else {
      console.log(`Enhanced file not found or not provided: ${enhancedFilePath}`);
      console.log('Generating sample data instead...');
      
      // Generate sample data
      result = await generateSampleData(scanId);
    }
    
    // Disconnect from Redis
    await client.disconnect();
    console.log('Disconnected from Redis');
    
    console.log(result.message);
    process.exit(result.success ? 0 : 1);
  } catch (error) {
    console.error(`Error in main function: ${error.message}`);
    
    // Disconnect from Redis
    try {
      await client.disconnect();
    } catch (err) {
      console.error(`Error disconnecting from Redis: ${err.message}`);
    }
    
    process.exit(1);
  }
}

// Run the main function
main();
