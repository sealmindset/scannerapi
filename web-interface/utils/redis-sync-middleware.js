/**
 * Redis Synchronization Middleware
 * 
 * This script provides middleware functions to ensure scan results are properly
 * synchronized with Redis, allowing for report editing and other operations.
 */

const fs = require('fs');
const path = require('path');
const redis = require('./redis');
const scanMetadataSync = require('./scan-metadata-sync');

/**
 * Synchronize a specific scan result file with Redis
 * @param {string} resultsFilePath - Full path to the results JSON file
 * @returns {Promise<Object>} - Result object with success status and scan ID
 */
async function syncScanResultToRedis(resultsFilePath) {
  try {
    console.log(`Syncing scan result to Redis: ${resultsFilePath}`);
    
    // Check if file exists
    if (!fs.existsSync(resultsFilePath)) {
      return {
        success: false,
        message: `Results file not found: ${resultsFilePath}`,
        scanId: null
      };
    }
    
    // Read and parse the results file
    const resultsContent = fs.readFileSync(resultsFilePath, 'utf8');
    const scanResults = JSON.parse(resultsContent);
    
    // Extract the actual scan ID from the results
    const filename = path.basename(resultsFilePath, '.json');
    const actualScanId = scanResults.scan_id || scanResults.scan_info?.scan_id || filename;
    
    console.log(`Extracted scan ID: ${actualScanId} from file: ${filename}`);
    
    // Check if this is an enhanced result
    const isEnhanced = scanResults.enhancement_info !== undefined;
    
    // Check if a report exists for this scan
    const reportFilename = `report_${actualScanId}.html`;
    const reportPath = path.join(__dirname, '../../reports', reportFilename);
    const hasReport = fs.existsSync(reportPath);
    
    // Count vulnerabilities
    let vulnCount = 0;
    if (scanResults.vulnerabilities && Array.isArray(scanResults.vulnerabilities)) {
      vulnCount = scanResults.vulnerabilities.length;
    } else if (scanResults.results && Array.isArray(scanResults.results)) {
      vulnCount = scanResults.results.length;
    }
    
    // Get file stats
    const stats = fs.statSync(resultsFilePath);
    
    // Prepare metadata
    const metadata = {
      timestamp: stats.mtime.getTime().toString(),
      createdAt: stats.birthtime.getTime().toString(),
      title: scanResults.title || scanResults.scan_info?.title || 'Untitled Scan',
      description: scanResults.description || scanResults.scan_info?.description || '',
      targetUrl: scanResults.target_url || scanResults.scan_info?.target_url || '',
      status: 'complete',
      enhanced: isEnhanced.toString(),
      hasReport: hasReport.toString(),
      vulnerabilityCount: vulnCount.toString(),
      filename: filename // Store the filename without extension for reference
    };
    
    // If enhanced, add provider and model info
    if (isEnhanced && scanResults.enhancement_info) {
      metadata.provider = scanResults.enhancement_info.provider || '';
      metadata.model = scanResults.enhancement_info.model || '';
    }
    
    // Store in Redis using the actual scan ID
    await redis.storeScanMetadata(actualScanId, metadata);
    
    // Create mapping from filename to actual scan ID if they're different
    if (actualScanId !== filename) {
      await redis.storeScanIdMapping(filename, actualScanId);
    }
    
    console.log(`Successfully synced scan result to Redis with ID: ${actualScanId}`);
    
    return {
      success: true,
      message: 'Scan result successfully synced to Redis',
      scanId: actualScanId
    };
  } catch (error) {
    console.error(`Error syncing scan result to Redis: ${error.message}`);
    return {
      success: false,
      message: `Error: ${error.message}`,
      scanId: null
    };
  }
}

/**
 * Middleware function to ensure a scan ID exists in Redis
 * @param {string} scanId - The scan ID to check
 * @returns {Promise<Object>} - Result object with success status and scan ID
 */
async function ensureScanIdInRedis(scanId) {
  try {
    console.log(`Ensuring scan ID exists in Redis: ${scanId}`);
    
    // Check if scan ID exists in Redis
    const metadata = await redis.getScanMetadata(scanId);
    
    if (metadata) {
      console.log(`Scan ID ${scanId} already exists in Redis`);
      return {
        success: true,
        message: 'Scan ID already exists in Redis',
        scanId: scanId
      };
    }
    
    // Try to find the scan results file
    const resultsDir = path.join(__dirname, '../../results');
    
    // Try different naming patterns
    const possibleFilenames = [
      `${scanId}.json`,
      `enhanced_${scanId}.json`,
      `results_${scanId}.json`
    ];
    
    let resultsFilePath = null;
    
    for (const filename of possibleFilenames) {
      const filePath = path.join(resultsDir, filename);
      if (fs.existsSync(filePath)) {
        resultsFilePath = filePath;
        break;
      }
    }
    
    // If no exact match, try to find files containing the scan ID
    if (!resultsFilePath) {
      console.log(`No exact filename match for scan ID ${scanId}, searching with regex...`);
      
      const files = fs.readdirSync(resultsDir);
      const regex = new RegExp(`.*${scanId}.*\\.json$`);
      
      const matchingFiles = files.filter(file => regex.test(file));
      
      if (matchingFiles.length > 0) {
        // Prefer enhanced results if available
        const enhancedMatch = matchingFiles.find(file => file.includes('enhanced'));
        resultsFilePath = path.join(resultsDir, enhancedMatch || matchingFiles[0]);
      }
    }
    
    if (!resultsFilePath) {
      return {
        success: false,
        message: `Could not find results file for scan ID: ${scanId}`,
        scanId: null
      };
    }
    
    // Sync the found results file to Redis
    return await syncScanResultToRedis(resultsFilePath);
  } catch (error) {
    console.error(`Error ensuring scan ID in Redis: ${error.message}`);
    return {
      success: false,
      message: `Error: ${error.message}`,
      scanId: null
    };
  }
}

/**
 * Express middleware to ensure scan ID exists in Redis
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
async function expressScanIdMiddleware(req, res, next) {
  try {
    // Extract scan ID from request parameters
    const scanId = req.params.scanId;
    
    if (!scanId) {
      return next();
    }
    
    // Ensure scan ID exists in Redis
    const result = await ensureScanIdInRedis(scanId);
    
    if (!result.success) {
      console.warn(`Warning: ${result.message}`);
    }
    
    // Continue with request processing regardless of result
    next();
  } catch (error) {
    console.error(`Error in scan ID middleware: ${error.message}`);
    next();
  }
}

module.exports = {
  syncScanResultToRedis,
  ensureScanIdInRedis,
  expressScanIdMiddleware
};
