#!/usr/bin/env node
/**
 * Redis Sync Script
 * 
 * This script synchronizes scan metadata from the filesystem to Redis.
 * It's used to ensure that metadata updates made directly to files
 * (e.g., by the update_scan_metadata.py script) are reflected in Redis.
 */

// Load environment variables
require('dotenv').config({ path: '../../.env' });

const fs = require('fs');
const path = require('path');
const redis = require('./redis');

// Path to results directory
const resultsDir = path.join(__dirname, '../../results');

/**
 * Synchronize a specific scan's metadata with Redis
 * @param {string} scanId - The ID of the scan to synchronize
 * @returns {Promise<boolean>} - True if successful, false otherwise
 */
async function syncScanMetadata(scanId) {
  try {
    const metadataFile = path.join(resultsDir, `${scanId}_metadata.json`);
    
    if (!fs.existsSync(metadataFile)) {
      console.error(`Metadata file not found for scan ID: ${scanId}`);
      return false;
    }
    
    // Read the metadata file
    const metadata = JSON.parse(fs.readFileSync(metadataFile, 'utf8'));
    
    // Store in Redis
    const result = await redis.storeScanMetadata(scanId, metadata);
    
    if (result) {
      console.log(`Successfully synchronized metadata for scan ID: ${scanId}`);
      return true;
    } else {
      console.error(`Failed to store metadata in Redis for scan ID: ${scanId}`);
      return false;
    }
  } catch (error) {
    console.error(`Error synchronizing metadata for scan ID ${scanId}:`, error);
    return false;
  }
}

/**
 * Synchronize all scan metadata files with Redis
 * @returns {Promise<void>}
 */
async function syncAllMetadata() {
  try {
    // Get all metadata files
    const files = fs.readdirSync(resultsDir);
    const metadataFiles = files.filter(file => file.endsWith('_metadata.json'));
    
    if (metadataFiles.length === 0) {
      console.log('No metadata files found to synchronize');
      return;
    }
    
    console.log(`Found ${metadataFiles.length} metadata files to synchronize`);
    
    // Process each file
    let successCount = 0;
    for (const file of metadataFiles) {
      const scanId = file.replace('_metadata.json', '');
      const success = await syncScanMetadata(scanId);
      if (success) successCount++;
    }
    
    console.log(`Synchronized ${successCount} of ${metadataFiles.length} metadata files with Redis`);
  } catch (error) {
    console.error('Error synchronizing metadata files:', error);
  }
}

/**
 * Main function
 */
async function main() {
  const args = process.argv.slice(2);
  
  if (args.length > 0) {
    // Sync specific scan ID
    const scanId = args[0];
    const success = await syncScanMetadata(scanId);
    process.exit(success ? 0 : 1);
  } else {
    // Sync all metadata
    await syncAllMetadata();
    process.exit(0);
  }
}

// Ensure Redis connection is established before running the main function
(async () => {
  try {
    // Explicitly ensure Redis connection is established
    const connected = await redis.ensureConnection();
    
    if (!connected) {
      console.error('Failed to connect to Redis. Please check your Redis configuration.');
      process.exit(1);
    }
    
    // Run the main function after connection is established
    await main();
  } catch (error) {
    console.error('Unhandled error:', error);
    process.exit(1);
  }
})();
