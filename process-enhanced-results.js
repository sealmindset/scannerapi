/**
 * Script to manually process enhanced results and store them in Redis
 * 
 * Usage: node process-enhanced-results.js <scanId> <enhancedFilePath>
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

if (!scanId || !enhancedFilePath) {
  console.error('Usage: node process-enhanced-results.js <scanId> <enhancedFilePath>');
  process.exit(1);
}

// Check if enhanced file exists
if (!fs.existsSync(enhancedFilePath)) {
  console.error(`Enhanced file not found: ${enhancedFilePath}`);
  process.exit(1);
}

// Function to cache report field in Redis
async function cacheReportField(scanId, field, content, expiry = 86400) {
  try {
    // Create key in format scanId:field
    const key = `scan:${scanId}:${field}`;
    
    // Store in Redis with expiry
    await client.set(key, content);
    await client.expire(key, expiry);
    
    return true;
  } catch (error) {
    console.error(`Error caching report field: ${error.message}`);
    return false;
  }
}

// Main function to process enhanced results
async function processEnhancedResults() {
  try {
    console.log(`Processing enhanced results from ${enhancedFilePath}`);
    
    // Connect to Redis
    await client.connect();
    console.log('Connected to Redis');
    
    // Read the enhanced content
    const enhancedContent = JSON.parse(fs.readFileSync(enhancedFilePath, 'utf8'));
    console.log(`Read enhanced content with ${Object.keys(enhancedContent.scanners).length} scanners`);
    
    // Store vulnerabilities in Redis
    let vulnCount = 0;
    for (const scanner of Object.keys(enhancedContent.scanners)) {
      if (enhancedContent.scanners[scanner].vulnerabilities) {
        const vulns = enhancedContent.scanners[scanner].vulnerabilities;
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
      timestamp: enhancedContent.timestamp,
      target: enhancedContent.target,
      summary: enhancedContent.summary,
      title: enhancedContent.title || enhancedContent.scan_info?.title || `Scan ${scanId}`
    }));
    
    // Store vulnerability list
    const vulnList = [];
    for (const scanner of Object.keys(enhancedContent.scanners)) {
      if (enhancedContent.scanners[scanner].vulnerabilities) {
        for (const vuln of enhancedContent.scanners[scanner].vulnerabilities) {
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
    
    // Disconnect from Redis
    await client.disconnect();
    console.log('Disconnected from Redis');
    
    return { success: true, message: `Enhanced content processed and stored for scan ${scanId}` };
  } catch (error) {
    console.error(`Error processing enhanced results: ${error.message}`);
    
    // Disconnect from Redis
    try {
      await client.disconnect();
    } catch (err) {
      console.error(`Error disconnecting from Redis: ${err.message}`);
    }
    
    return { success: false, message: `Error: ${error.message}` };
  }
}

// Run the process
processEnhancedResults()
  .then(result => {
    console.log(result.message);
    process.exit(result.success ? 0 : 1);
  })
  .catch(error => {
    console.error(`Unhandled error: ${error.message}`);
    process.exit(1);
  });
