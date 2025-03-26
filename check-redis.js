/**
 * Script to check Redis for scan data and diagnose issues
 * 
 * Usage: node check-redis.js <scanId>
 */

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

if (!scanId) {
  console.error('Usage: node check-redis.js <scanId>');
  process.exit(1);
}

// Function to get cached report field from Redis
async function getCachedReportField(scanId, field) {
  try {
    // Create key in format report:scanId:field
    const key = `report:${scanId}:${field}`;
    
    // Get from Redis
    const value = await client.get(key);
    
    return value;
  } catch (error) {
    console.error(`Error getting cached report field: ${error.message}`);
    return null;
  }
}

// Function to list all keys for a scan
async function listKeysForScan(scanId) {
  try {
    const keys = await client.keys(`report:${scanId}:*`);
    return keys;
  } catch (error) {
    console.error(`Error listing keys: ${error.message}`);
    return [];
  }
}

// Main function to check Redis
async function checkRedis() {
  try {
    console.log(`Checking Redis for scan ID: ${scanId}`);
    
    // Connect to Redis
    await client.connect();
    console.log('Connected to Redis');
    
    // List all keys for this scan
    const keys = await listKeysForScan(scanId);
    console.log(`Found ${keys.length} keys for scan ID ${scanId}`);
    
    if (keys.length === 0) {
      console.log('No data found in Redis for this scan ID.');
      await client.disconnect();
      return;
    }
    
    // Get metadata
    const metadata = await getCachedReportField(scanId, 'metadata');
    console.log('\nMetadata:');
    if (metadata) {
      console.log(JSON.parse(metadata));
    } else {
      console.log('No metadata found');
    }
    
    // Get vulnerability list
    const vulnList = await getCachedReportField(scanId, 'vulnList');
    console.log('\nVulnerability List:');
    if (vulnList) {
      const vulns = JSON.parse(vulnList);
      console.log(`Found ${vulns.length} vulnerabilities`);
      
      // Print first 3 vulnerabilities
      for (let i = 0; i < Math.min(vulns.length, 3); i++) {
        console.log(`- ${vulns[i].id}: ${vulns[i].title} (${vulns[i].severity})`);
      }
      
      // Check if we have details for each vulnerability
      console.log('\nChecking vulnerability details:');
      for (let i = 0; i < Math.min(vulns.length, 3); i++) {
        const vulnId = vulns[i].id;
        const title = await getCachedReportField(scanId, `vuln:${vulnId}:title`);
        const description = await getCachedReportField(scanId, `vuln:${vulnId}:description`);
        
        console.log(`- ${vulnId}: Title=${title ? 'Found' : 'Missing'}, Description=${description ? 'Found' : 'Missing'}`);
      }
    } else {
      console.log('No vulnerability list found');
    }
    
    // Disconnect from Redis
    await client.disconnect();
    console.log('\nDisconnected from Redis');
  } catch (error) {
    console.error(`Error checking Redis: ${error.message}`);
    
    // Disconnect from Redis
    try {
      await client.disconnect();
    } catch (err) {
      console.error(`Error disconnecting from Redis: ${err.message}`);
    }
  }
}

// Run the check
checkRedis()
  .then(() => {
    process.exit(0);
  })
  .catch(error => {
    console.error(`Unhandled error: ${error.message}`);
    process.exit(1);
  });
