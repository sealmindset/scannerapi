const redis = require('redis');

// Get Redis configuration from environment variables
const redisHost = process.env.LLM_REDIS_HOST || 'localhost';
const redisPort = process.env.LLM_REDIS_PORT || 6379;
const redisDb = process.env.LLM_REDIS_DB || 0;
const redisPassword = process.env.LLM_REDIS_PASSWORD || '';

// Create Redis client with modern API
let redisUrl = `redis://${redisHost}:${redisPort}/${redisDb}`;

// Add password if provided
if (redisPassword) {
  redisUrl = `redis://:${redisPassword}@${redisHost}:${redisPort}/${redisDb}`;
}

const client = redis.createClient({
  url: redisUrl,
  socket: {
    reconnectStrategy: (retries) => {
      // Exponential backoff with a maximum delay of 10 seconds
      const delay = Math.min(Math.pow(2, retries) * 100, 10000);
      console.log(`Redis reconnect attempt ${retries}, retrying in ${delay}ms`);
      return delay;
    }
  }
});

// Variable to track connection state
let isConnected = false;

// Function to ensure Redis is connected
async function ensureConnection() {
  if (!isConnected) {
    try {
      console.log(`Attempting to connect to Redis at ${redisHost}:${redisPort} (DB: ${redisDb})...`);
      
      // Check if client is already connected
      if (client.isOpen) {
        console.log('Redis client is already connected');
        isConnected = true;
        return true;
      }
      
      // Set a timeout for connection attempts
      const connectionPromise = client.connect();
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Connection timeout after 5 seconds')), 5000);
      });
      
      await Promise.race([connectionPromise, timeoutPromise]);
      
      // Verify connection with a ping
      const pingResult = await client.ping();
      if (pingResult === 'PONG') {
        isConnected = true;
        console.log('Successfully connected to Redis server and verified with PING');
      } else {
        throw new Error(`Unexpected ping response: ${pingResult}`);
      }
    } catch (err) {
      // Handle the case where the client is already connected
      if (err.message && err.message.includes('Socket already opened')) {
        console.log('Redis client is already connected');
        isConnected = true;
        return true;
      }
      
      isConnected = false;
      console.error('Redis connection error:', err);
      console.error('Redis connection details:');
      console.error(`- Host: ${redisHost}`);
      console.error(`- Port: ${redisPort}`);
      console.error(`- Database: ${redisDb}`);
      console.error(`- Password set: ${redisPassword ? 'Yes' : 'No'}`);
      console.error('Redis operations will be skipped. Make sure Redis is running and properly configured in .env file');
      return false;
    }
  }
  return isConnected;
}

// Connect to Redis on startup and handle events
(async () => {
  try {
    await ensureConnection();
    
    // Set up event handlers
    client.on('error', (err) => {
      console.error('Redis client error:', err);
      isConnected = false;
    });
    
    client.on('reconnecting', () => {
      console.log('Redis client reconnecting...');
      isConnected = false;
    });
    
    client.on('connect', () => {
      console.log('Redis client connected');
      isConnected = true;
    });
    
    client.on('ready', () => {
      console.log('Redis client ready');
      isConnected = true;
    });
    
    client.on('end', () => {
      console.log('Redis client connection ended');
      isConnected = false;
    });
    
    // Attempt an initial ping to verify connection
    const pingResult = await client.ping();
    console.log('Redis ping result:', pingResult);
  } catch (err) {
    console.error('Failed to initialize Redis connection:', err);
  }
})();

// Handle Redis connection events
client.on('error', (err) => {
  isConnected = false;
  console.error('Redis error:', err);
});

client.on('ready', () => {
  isConnected = true;
  console.log('Redis client is ready');
});

client.on('reconnecting', () => {
  isConnected = false;
  console.log('Reconnecting to Redis server...');
});

client.on('connect', () => {
  isConnected = true;
  console.log('Redis connection established');
});

client.on('end', () => {
  isConnected = false;
  console.log('Redis connection ended');
});

// No need to promisify as the new client already returns promises

/**
 * Cache report content in Redis
 * @param {string} scanId - Scan ID
 * @param {string} field - Field name (description, risk, impact, examples, remediation)
 * @param {string} content - Content to cache
 * @param {number} [expiry=86400] - Cache expiry in seconds (default: 24 hours)
 * @returns {Promise<boolean>} - Success status
 */
async function cacheReportField(scanId, field, content, expiry = 86400) {
  // Ensure Redis is connected before proceeding
  const connected = await ensureConnection();
  if (!connected) {
    console.warn('Redis not connected, skipping cacheReportField operation');
    return false;
  }
  
  try {
    const key = `report:${scanId}:${field}`;
    await client.set(key, content, { EX: expiry });
    return true;
  } catch (error) {
    console.error(`Error caching report field: ${error.message}`);
    isConnected = false; // Mark as disconnected on error
    return false;
  }
}

/**
 * Get cached report field from Redis
 * @param {string} scanId - Scan ID
 * @param {string} field - Field name (description, risk, impact, examples, remediation)
 * @returns {Promise<string|null>} - Cached content or null if not found
 */
async function getCachedReportField(scanId, field) {
  // Ensure Redis is connected before proceeding
  const connected = await ensureConnection();
  if (!connected) {
    console.warn('Redis not connected, skipping getCachedReportField operation');
    return null;
  }
  
  try {
    const key = `report:${scanId}:${field}`;
    return await client.get(key);
  } catch (error) {
    console.error(`Error getting cached report field: ${error.message}`);
    isConnected = false; // Mark as disconnected on error
    return null;
  }
}

/**
 * Delete a cached report field from Redis
 * @param {string} scanId - Scan ID
 * @param {string} field - Field name to delete
 * @returns {Promise<boolean>} - Success status
 */
async function deleteCachedReportField(scanId, field) {
  // Ensure Redis is connected before proceeding
  const connected = await ensureConnection();
  if (!connected) {
    console.warn('Redis not connected, skipping deleteCachedReportField operation');
    return false;
  }
  
  try {
    const key = `report:${scanId}:${field}`;
    await client.del(key);
    console.log(`Deleted Redis key: ${key}`);
    return true;
  } catch (error) {
    console.error(`Error deleting cached report field: ${error.message}`);
    isConnected = false; // Mark as disconnected on error
    return false;
  }
}

/**
 * Delete all cached fields for a report
 * @param {string} scanId - Scan ID
 * @returns {Promise<boolean>} - Success status
 */
async function clearReportCache(scanId) {
  // Ensure Redis is connected before proceeding
  const connected = await ensureConnection();
  if (!connected) {
    console.warn('Redis not connected, skipping clearReportCache operation');
    return false;
  }
  
  try {
    // Get all keys matching the pattern
    const keys = await client.keys(`report:${scanId}:*`);
    console.log(`Found ${keys.length} Redis keys to delete for scan ID: ${scanId}`);
    
    // Delete each key individually
    if (keys.length > 0) {
      // Using pipeline for better performance
      const pipeline = client.multi();
      for (const key of keys) {
        pipeline.del(key);
      }
      await pipeline.exec();
      console.log(`Successfully deleted ${keys.length} Redis keys for scan ID: ${scanId}`);
    }
    
    // Also clear the complete vulnerability data
    await client.del(`report:${scanId}:complete_vulnerability_data`);
    
    return true;
  } catch (error) {
    console.error(`Error clearing report cache: ${error.message}`);
    isConnected = false; // Mark as disconnected on error
    return false;
  }
}

/**
 * Store scan metadata in Redis
 * @param {string} scanId - Scan ID
 * @param {Object} metadata - Scan metadata
 * @param {string} metadata.title - Scan title
 * @param {string} metadata.description - Scan description
 * @param {string} metadata.timestamp - Scan timestamp
 * @param {string} metadata.targetUrl - Target URL
 * @param {boolean} metadata.enhanced - Whether the scan has been enhanced with LLM
 * @param {string} metadata.provider - LLM provider used (if enhanced)
 * @param {string} metadata.model - LLM model used (if enhanced)
 * @param {string} metadata.status - Scan status (complete, failed, etc.)
 * @returns {Promise<boolean>} - Success status
 */
async function storeScanMetadata(scanId, metadata) {
  // Ensure Redis is connected before proceeding
  const connected = await ensureConnection();
  if (!connected) {
    console.warn('Redis not connected, skipping storeScanMetadata operation');
    return false;
  }
  
  try {
    console.log(`Storing metadata for scan ID: ${scanId}`);
    
    // Convert metadata to a flat object if it's not already
    const flatMetadata = {};
    
    // Process the metadata object to ensure it's in the right format for Redis hSet
    if (metadata && typeof metadata === 'object') {
      // First, stringify any nested objects or arrays
      for (const [key, value] of Object.entries(metadata)) {
        if (value === null) {
          flatMetadata[key] = '';
        } else if (typeof value === 'object') {
          flatMetadata[key] = JSON.stringify(value);
        } else {
          flatMetadata[key] = String(value);
        }
      }
      
      // Store the metadata as a hash
      const key = `scan:${scanId}:metadata`;
      
      // Delete existing metadata first
      await client.del(key);
      
      // Only attempt to store if we have data
      if (Object.keys(flatMetadata).length > 0) {
        await client.hSet(key, flatMetadata);
        console.log(`Successfully stored metadata for scan ID: ${scanId}`);
      } else {
        console.warn(`No metadata to store for scan ID: ${scanId}`);
      }
      
      // Add to the scan list for quick access
      await client.zAdd('scans', [{
        score: Date.now(),
        value: scanId
      }]);
      
      return true;
    } else {
      console.error(`Invalid metadata format for scan ID: ${scanId}`);
      return false;
    }
  } catch (error) {
    console.error(`Error storing scan metadata: ${error.message}`);
    return false;
  }
}

/**
 * Get scan metadata from Redis
 * @param {string} scanId - Scan ID
 * @returns {Promise<Object|null>} - Scan metadata or null if not found
 */
async function getScanMetadata(scanId) {
  if (!isConnected) {
    console.warn('Redis not connected, skipping getScanMetadata operation');
    return null;
  }
  
  try {
    const key = `scan:${scanId}:metadata`;
    const metadata = await client.hGetAll(key);
    
    // If empty object is returned, the key doesn't exist
    return Object.keys(metadata).length > 0 ? metadata : null;
  } catch (error) {
    console.error(`Error getting scan metadata: ${error.message}`);
    return null;
  }
}

/**
 * Get all scan IDs from Redis, sorted by timestamp (newest first)
 * @param {number} [limit=50] - Maximum number of scan IDs to return
 * @param {number} [offset=0] - Offset for pagination
 * @returns {Promise<Array<string>>} - Array of scan IDs
 */
async function getAllScanIds(limit = 50, offset = 0) {
  // Ensure Redis is connected before proceeding
  const connected = await ensureConnection();
  if (!connected) {
    console.warn('Redis not connected, falling back to filesystem for scan IDs');
    return getScansFromFilesystem(limit, offset);
  }
  
  try {
    // Get scan IDs from sorted set, newest first
    const scanIds = await client.zRange('scans', offset, offset + limit - 1, {
      REV: true // Reverse order (newest first)
    });
    
    if (scanIds.length === 0) {
      console.log('No scan IDs found in Redis, falling back to filesystem');
      return getScansFromFilesystem(limit, offset);
    }
    
    return scanIds;
  } catch (error) {
    console.error(`Error getting scan IDs from Redis: ${error.message}`);
    return getScansFromFilesystem(limit, offset);
  }
}

/**
 * Get scan IDs from filesystem as a fallback when Redis is not available
 * @param {number} limit - Maximum number of scan IDs to return
 * @param {number} offset - Offset for pagination
 * @returns {Array<string>} - Array of scan IDs
 */
function getScansFromFilesystem(limit = 50, offset = 0) {
  try {
    const fs = require('fs');
    const path = require('path');
    const resultsDir = path.join(__dirname, '../../results');
    
    if (!fs.existsSync(resultsDir)) {
      console.warn('Results directory does not exist');
      return [];
    }
    
    // Get all JSON files in the results directory
    const allFiles = fs.readdirSync(resultsDir)
      .filter(file => file.endsWith('.json') && !file.includes('_metadata') && !file.includes('_enhanced'));
    
    // Sort by modification time (most recent first)
    const sortedFiles = allFiles.sort((a, b) => {
      const statA = fs.statSync(path.join(resultsDir, a));
      const statB = fs.statSync(path.join(resultsDir, b));
      return statB.mtime.getTime() - statA.mtime.getTime();
    });
    
    // Apply pagination
    const paginatedFiles = sortedFiles.slice(offset, offset + limit);
    
    // Extract scan IDs from filenames
    const scanIds = paginatedFiles.map(file => file.replace('.json', ''));
    console.log(`Found ${scanIds.length} scan IDs from filesystem`);
    return scanIds;
  } catch (error) {
    console.error(`Error getting scans from filesystem: ${error.message}`);
    return [];
  }
}

/**
 * Get metadata for multiple scans
 * @param {Array<string>} scanIds - Array of scan IDs
 * @returns {Promise<Array<Object>>} - Array of scan metadata objects
 */
async function getMultipleScanMetadata(scanIds) {
  try {
    const promises = scanIds.map(scanId => getScanMetadata(scanId));
    const results = await Promise.all(promises);
    
    // Filter out null results and add scanId to each metadata object
    return results
      .map((metadata, index) => {
        if (!metadata) return null;
        return { ...metadata, scanId: scanIds[index] };
      })
      .filter(item => item !== null);
  } catch (error) {
    console.error(`Error getting multiple scan metadata: ${error.message}`);
    return [];
  }
}

/**
 * Update scan enhancement status
 * @param {string} scanId - Scan ID
 * @param {boolean} enhanced - Whether the scan has been enhanced
 * @param {string} provider - LLM provider used
 * @param {string} model - LLM model used
 * @returns {Promise<boolean>} - Success status
 */
async function updateScanEnhancementStatus(scanId, enhanced, provider = null, model = null) {
  try {
    const key = `scan:${scanId}:metadata`;
    const updates = {
      enhanced: enhanced.toString(),
      enhancementTimestamp: Date.now().toString()
    };
    
    if (provider) updates.provider = provider;
    if (model) updates.model = model;
    
    await client.hSet(key, updates);
    return true;
  } catch (error) {
    console.error(`Error updating scan enhancement status: ${error.message}`);
    return false;
  }
}

/**
 * Store a mapping from filename to actual scan ID
 * @param {string} filename - The filename (without extension)
 * @param {string} actualScanId - The actual scan ID
 * @returns {Promise<boolean>} - Success status
 */
async function storeScanIdMapping(filename, actualScanId) {
  try {
    const key = `scanid_map:${filename}`;
    await client.set(key, actualScanId);
    return true;
  } catch (error) {
    console.error(`Error storing scan ID mapping: ${error.message}`);
    return false;
  }
}

/**
 * Get the actual scan ID from a filename
 * @param {string} filename - The filename (without extension)
 * @returns {Promise<string|null>} - The actual scan ID or null if not found
 */
async function getActualScanId(filename) {
  try {
    const key = `scanid_map:${filename}`;
    const actualScanId = await client.get(key);
    return actualScanId;
  } catch (error) {
    console.error(`Error getting actual scan ID: ${error.message}`);
    return null;
  }
}

module.exports = {
  cacheReportField,
  getCachedReportField,
  deleteCachedReportField,
  clearReportCache,
  storeScanMetadata,
  getScanMetadata,
  getAllScanIds,
  getMultipleScanMetadata,
  updateScanEnhancementStatus,
  storeScanIdMapping,
  getActualScanId,
  ensureConnection,
  client,
  isConnected
};
