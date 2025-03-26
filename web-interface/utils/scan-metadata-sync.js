/**
 * Scan Metadata Synchronization Utility
 * 
 * This module provides functions to synchronize scan metadata between
 * the filesystem (JSON files) and Redis for the hybrid storage approach.
 */

const fs = require('fs');
const path = require('path');
const redis = require('./redis');

/**
 * Synchronize scan metadata from filesystem to Redis
 * This ensures Redis has the latest metadata even if it was restarted
 * @returns {Promise<{success: boolean, count: number, errors: Array}>} - Result with count of synced scans
 */
async function syncFromFilesystemToRedis() {
  try {
    const resultsDir = path.join(__dirname, '../../results');
    const reportsDir = path.join(__dirname, '../../reports');
    
    // Ensure directories exist
    if (!fs.existsSync(resultsDir)) {
      console.warn('Results directory does not exist');
      return { success: false, count: 0, errors: ['Results directory does not exist'] };
    }
    
    // Get all JSON files in the results directory
    const allFiles = fs.readdirSync(resultsDir).filter(file => file.endsWith('.json'));
    
    // First, identify all scan IDs and their enhanced status
    const scanMap = new Map();
    
    allFiles.forEach(file => {
      if (file.endsWith('_enhanced.json')) {
        // This is an enhanced file
        const scanId = file.replace('_enhanced.json', '');
        if (!scanMap.has(scanId)) {
          scanMap.set(scanId, { hasEnhanced: true });
        } else {
          scanMap.get(scanId).hasEnhanced = true;
        }
      } else {
        // This is a regular scan file
        const scanId = file.replace('.json', '');
        if (!scanMap.has(scanId)) {
          scanMap.set(scanId, { hasEnhanced: false });
        }
      }
    });
    
    // Only process the base scan files (not enhanced ones)
    const files = allFiles.filter(file => !file.endsWith('_enhanced.json'));
    
    let syncedCount = 0;
    const errors = [];
    
    // Process each file
    for (const file of files) {
      try {
        const scanId = file.replace('.json', '');
        const filePath = path.join(resultsDir, file);
        const stats = fs.statSync(filePath);
        
        // Read the JSON file
        const scanResults = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        
        // Check if enhanced version exists
        const enhancedFilePath = path.join(resultsDir, `${scanId}_enhanced.json`);
        const isEnhanced = fs.existsSync(enhancedFilePath);
        
        // Check if report exists
        const reportPath = path.join(reportsDir, `report_${scanId}.html`);
        const hasReport = fs.existsSync(reportPath);
        
        // Use the enhanced status from our scan map
        const scanMapInfo = scanMap.get(scanId) || { hasEnhanced: isEnhanced };
        const isEnhancedFromMap = scanMapInfo.hasEnhanced;
        
        // Extract basic metadata from scan results
        // Handle different formats of scan results to extract vulnerability count
        let vulnCount = 0;
        if (Array.isArray(scanResults.vulnerabilities)) {
          vulnCount = scanResults.vulnerabilities.length;
        } else if (scanResults.scan_results && Array.isArray(scanResults.scan_results.vulnerabilities)) {
          vulnCount = scanResults.scan_results.vulnerabilities.length;
        }
        
        // Extract the actual scan ID from the results if available
        const actualScanId = scanResults.scan_id || scanResults.scan_info?.scan_id || scanId;
        
        const metadata = {
          timestamp: stats.mtime.getTime().toString(),
          createdAt: stats.birthtime.getTime().toString(),
          title: scanResults.title || scanResults.scan_info?.title || 'Untitled Scan',
          description: scanResults.description || scanResults.scan_info?.description || '',
          targetUrl: scanResults.target_url || scanResults.scan_info?.target_url || '',
          status: 'complete',
          enhanced: isEnhancedFromMap.toString(), // Use the status from our map
          hasReport: hasReport.toString(),
          vulnerabilityCount: vulnCount.toString(),
          filename: scanId // Store the filename without extension for reference
        };
        
        // If enhanced, try to get provider and model info
        if (isEnhancedFromMap) {
          try {
            const enhancedResults = JSON.parse(fs.readFileSync(enhancedFilePath, 'utf8'));
            metadata.provider = enhancedResults.enhancement_info?.provider || '';
            metadata.model = enhancedResults.enhancement_info?.model || '';
            
            // For enhanced scans, use the enhanced file's timestamp as the most recent modification
            const enhancedStats = fs.statSync(enhancedFilePath);
            metadata.timestamp = enhancedStats.mtime.getTime().toString();
          } catch (enhancedError) {
            console.warn(`Error reading enhanced file for ${scanId}: ${enhancedError.message}`);
          }
        }
        
        console.log(`Storing metadata with actual scan ID: ${actualScanId} (from filename: ${scanId})`);
        
        // Store in Redis using the actual scan ID as the key
        await redis.storeScanMetadata(actualScanId, metadata);
        
        // Also store a mapping from filename to actual scan ID for backward compatibility
        if (actualScanId !== scanId) {
          await redis.storeScanIdMapping(scanId, actualScanId);
        }
        syncedCount++;
      } catch (error) {
        console.error(`Error processing file ${file}: ${error.message}`);
        errors.push(`Error processing file ${file}: ${error.message}`);
      }
    }
    
    return {
      success: true,
      count: syncedCount,
      errors: errors
    };
  } catch (error) {
    console.error(`Error synchronizing scan metadata: ${error.message}`);
    return {
      success: false,
      count: 0,
      errors: [error.message]
    };
  }
}

/**
 * Get all available scans with metadata
 * First tries to get from Redis, then falls back to filesystem if needed
 * @param {number} [limit=50] - Maximum number of scans to return
 * @param {number} [offset=0] - Offset for pagination
 * @returns {Promise<Array<Object>>} - Array of scan metadata objects
 */
async function getAllScansWithMetadata(limit = 50, offset = 0) {
  try {
    // Sync from filesystem first to ensure we have the latest data with actual scan IDs
    await syncFromFilesystemToRedis();
    
    // Get scan IDs from Redis
    const scanIds = await redis.getAllScanIds(limit, offset);
    
    if (scanIds.length > 0) {
      // Get metadata for each scan ID
      const scansWithMetadata = await redis.getMultipleScanMetadata(scanIds);
      
      // Log the scan IDs we're working with
      console.log(`Retrieved ${scansWithMetadata.length} scans with metadata`);
      
      return scansWithMetadata;
    } else {
      console.log('No scan IDs found in Redis after sync');
      return [];
    }
  } catch (error) {
    console.error(`Error getting all scans with metadata: ${error.message}`);
    return [];
  }
}

/**
 * Get detailed information about a specific scan
 * Combines Redis metadata with filesystem data
 * @param {string} scanId - Scan ID
 * @returns {Promise<Object|null>} - Detailed scan information or null if not found
 */
async function getScanDetails(scanId) {
  try {
    // Try to get metadata from Redis
    let metadata = await redis.getScanMetadata(scanId);
    
    // If not in Redis, check filesystem
    if (!metadata) {
      const resultsPath = path.join(__dirname, '../../results', `${scanId}.json`);
      
      if (!fs.existsSync(resultsPath)) {
        return null;
      }
      
      // Sync this scan to Redis
      await syncFromFilesystemToRedis();
      
      // Try to get metadata again
      metadata = await redis.getScanMetadata(scanId);
      
      if (!metadata) {
        // If still not found, create basic metadata
        const stats = fs.statSync(resultsPath);
        metadata = {
          scanId,
          timestamp: stats.mtime.getTime().toString(),
          createdAt: stats.birthtime.getTime().toString(),
          status: 'complete'
        };
      }
    }
    
    // Add file paths for convenience - check for all possible file patterns
    const resultsDir = path.join(__dirname, '../../results');
    const reportsDir = path.join(__dirname, '../../reports');
    
    // Find all result files that match this scanId
    const resultFiles = [];
    const reportFiles = [];
    
    // Only proceed if the directories exist
    if (fs.existsSync(resultsDir)) {
      const allResultFiles = fs.readdirSync(resultsDir);
      for (const file of allResultFiles) {
        if (file.includes(scanId) && file.endsWith('.json')) {
          resultFiles.push(path.join(resultsDir, file));
        }
      }
    }
    
    if (fs.existsSync(reportsDir)) {
      const allReportFiles = fs.readdirSync(reportsDir);
      for (const file of allReportFiles) {
        if (file.includes(scanId) && (file.endsWith('.html') || file.endsWith('.pdf'))) {
          reportFiles.push(path.join(reportsDir, file));
        }
      }
    }
    
    // Standard file paths for backward compatibility
    const standardResultsPath = path.join(resultsDir, `${scanId}.json`);
    const standardEnhancedPath = path.join(resultsDir, `${scanId}_enhanced.json`);
    const standardReportPath = path.join(reportsDir, `report_${scanId}.html`);
    
    const details = {
      ...metadata,
      scanId,
      resultsPath: fs.existsSync(standardResultsPath) ? standardResultsPath : null,
      enhancedResultsPath: fs.existsSync(standardEnhancedPath) ? standardEnhancedPath : null,
      reportPath: fs.existsSync(standardReportPath) ? standardReportPath : null,
      allResultFiles: resultFiles,
      allReportFiles: reportFiles,
      hasResults: fs.existsSync(standardResultsPath) || resultFiles.length > 0,
      hasEnhancedResults: fs.existsSync(standardEnhancedPath) || resultFiles.some(file => file.includes('enhanced')),
      hasReport: fs.existsSync(standardReportPath) || reportFiles.length > 0
    };
    
    return details;
  } catch (error) {
    console.error(`Error getting scan details for ${scanId}: ${error.message}`);
    return null;
  }
}

/**
 * Update scan metadata after enhancement
 * @param {string} scanId - Scan ID
 * @param {string} provider - LLM provider used
 * @param {string} model - LLM model used
 * @returns {Promise<boolean>} - Success status
 */
async function updateAfterEnhancement(scanId, provider, model) {
  try {
    // Update Redis metadata
    await redis.updateScanEnhancementStatus(scanId, true, provider, model);
    return true;
  } catch (error) {
    console.error(`Error updating after enhancement for ${scanId}: ${error.message}`);
    return false;
  }
}

/**
 * Search and filter scan metadata based on query parameters
 * @param {Object} filters - Filter parameters
 * @param {string} [filters.query] - Search query for scanId, title, or targetUrl
 * @param {string} [filters.enhanced] - Filter by enhancement status ('true' or 'false')
 * @param {string} [filters.severity] - Filter by vulnerability severity
 * @param {string} [filters.dateFrom] - Filter by date from (YYYY-MM-DD)
 * @param {string} [filters.dateTo] - Filter by date to (YYYY-MM-DD)
 * @param {number} [limit=50] - Maximum number of scans to return
 * @param {number} [offset=0] - Offset for pagination
 * @returns {Promise<Array<Object>>} - Array of filtered scan metadata objects
 */
async function searchScans(filters = {}, limit = 50, offset = 0) {
  try {
    // Sync from filesystem first to ensure we have the latest data
    await syncFromFilesystemToRedis();
    
    // Get all scan IDs from Redis
    const allScanIds = await redis.getAllScanIds(1000, 0); // Get a larger batch to filter through
    
    if (allScanIds.length === 0) {
      return [];
    }
    
    // Get metadata for all scans
    const allScans = await redis.getMultipleScanMetadata(allScanIds);
    
    // Apply filters
    let filteredScans = allScans;
    
    // Search query (case insensitive)
    if (filters.query && filters.query.trim() !== '') {
      const query = filters.query.trim().toLowerCase();
      filteredScans = filteredScans.filter(scan => {
        return (
          (scan.scanId && scan.scanId.toLowerCase().includes(query)) ||
          (scan.title && scan.title.toLowerCase().includes(query)) ||
          (scan.targetUrl && scan.targetUrl.toLowerCase().includes(query))
        );
      });
    }
    
    // Enhanced status
    if (filters.enhanced && (filters.enhanced === 'true' || filters.enhanced === 'false')) {
      filteredScans = filteredScans.filter(scan => 
        scan.enhanced === filters.enhanced
      );
    }
    
    // Severity filter
    if (filters.severity) {
      // This is a bit more complex as we need to check if any vulnerability has this severity
      // For simplicity, we'll just check if the scan has any vulnerabilities
      // A more accurate implementation would require checking the actual vulnerability severities
      if (filters.severity === 'Critical' || filters.severity === 'High') {
        filteredScans = filteredScans.filter(scan => 
          parseInt(scan.vulnerabilityCount || '0') > 0
        );
      } else if (filters.severity === 'Medium') {
        // Medium severity might have some vulnerabilities
        filteredScans = filteredScans.filter(scan => 
          parseInt(scan.vulnerabilityCount || '0') > 0
        );
      } else if (filters.severity === 'Low') {
        // Low severity might have fewer vulnerabilities
        filteredScans = filteredScans.filter(scan => 
          parseInt(scan.vulnerabilityCount || '0') >= 0
        );
      }
    }
    
    // Date range filters
    if (filters.dateFrom) {
      const dateFrom = new Date(filters.dateFrom).getTime();
      filteredScans = filteredScans.filter(scan => 
        parseInt(scan.timestamp || '0') >= dateFrom
      );
    }
    
    if (filters.dateTo) {
      // Add one day to include the end date fully
      const dateTo = new Date(filters.dateTo);
      dateTo.setDate(dateTo.getDate() + 1);
      const dateToTimestamp = dateTo.getTime();
      
      filteredScans = filteredScans.filter(scan => 
        parseInt(scan.timestamp || '0') <= dateToTimestamp
      );
    }
    
    // Sort by timestamp (newest first)
    filteredScans.sort((a, b) => {
      return parseInt(b.timestamp || '0') - parseInt(a.timestamp || '0');
    });
    
    // Apply pagination
    return filteredScans.slice(offset, offset + limit);
  } catch (error) {
    console.error(`Error searching scans: ${error.message}`);
    return [];
  }
}

module.exports = {
  syncFromFilesystemToRedis,
  getAllScansWithMetadata,
  getScanDetails,
  searchScans,
  updateAfterEnhancement
};
