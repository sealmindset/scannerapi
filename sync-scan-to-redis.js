#!/usr/bin/env node

/**
 * Sync Scan Results to Redis CLI Tool
 * 
 * This script allows syncing scan results to Redis from the command line.
 * It can be used as part of the report generation process or independently.
 * 
 * Usage:
 *   node sync-scan-to-redis.js <results-file-path>
 *   node sync-scan-to-redis.js --scan-id <scan-id>
 */

const path = require('path');
const fs = require('fs');
const redisSyncMiddleware = require('./web-interface/utils/redis-sync-middleware');

// Parse command line arguments
const args = process.argv.slice(2);

async function main() {
  try {
    if (args.length === 0) {
      console.error('Error: Missing required arguments');
      showUsage();
      process.exit(1);
    }

    let result;

    if (args[0] === '--scan-id' && args.length > 1) {
      // Sync by scan ID
      const scanId = args[1];
      console.log(`Syncing scan ID ${scanId} to Redis...`);
      result = await redisSyncMiddleware.ensureScanIdInRedis(scanId);
    } else {
      // Sync by file path
      const filePath = path.resolve(args[0]);
      
      if (!fs.existsSync(filePath)) {
        console.error(`Error: File not found: ${filePath}`);
        process.exit(1);
      }
      
      console.log(`Syncing file ${filePath} to Redis...`);
      result = await redisSyncMiddleware.syncScanResultToRedis(filePath);
    }

    if (result.success) {
      console.log(`Success: ${result.message}`);
      console.log(`Scan ID: ${result.scanId}`);
      process.exit(0);
    } else {
      console.error(`Error: ${result.message}`);
      process.exit(1);
    }
  } catch (error) {
    console.error(`Unexpected error: ${error.message}`);
    process.exit(1);
  }
}

function showUsage() {
  console.log(`
Sync Scan Results to Redis CLI Tool

Usage:
  node sync-scan-to-redis.js <results-file-path>
  node sync-scan-to-redis.js --scan-id <scan-id>

Examples:
  node sync-scan-to-redis.js results/scan123.json
  node sync-scan-to-redis.js --scan-id scan123
  `);
}

// Run the main function
main();
