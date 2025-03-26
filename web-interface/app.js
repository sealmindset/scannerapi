const express = require('express');
const { engine } = require('express-handlebars');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const methodOverride = require('method-override');
const http = require('http');
const { Server } = require('socket.io');
const { spawn } = require('child_process');
const redis = require('./utils/redis');
const redisSyncMiddleware = require('./utils/redis-sync-middleware');
const { setSession, getSession, getAllSessions, appendSessionOutput, updateSessionStatus } = require('./utils/session-store');

// Import routes
const reportEditorRoutes = require('./routes/report-editor');
const scanRoutes = require('./routes/scan');

// Import admin prompts routes
try {
  var adminPromptsRoutes = require('./routes/admin_prompts');
  console.log('Successfully loaded admin prompts routes');
} catch (error) {
  console.error('Error loading admin prompts routes:', error.message);
  // Create a dummy router to prevent app from crashing
  var adminPromptsRoutes = express.Router();
  adminPromptsRoutes.get('/', (req, res) => {
    res.status(500).send('Admin prompts module not available');
  });
}

// Import MCP routes
try {
  var mcpRoutes = require('./mcp/server');
  console.log('Successfully loaded MCP routes');
} catch (error) {
  console.error('Error loading MCP routes:', error.message);
  // Create a dummy router to prevent app from crashing
  var mcpRoutes = express.Router();
  mcpRoutes.get('/', (req, res) => {
    res.status(500).send('MCP module not available');
  });
}

// Import MCP admin routes
try {
  var mcpAdminRoutes = require('./routes/mcp_admin');
  console.log('Successfully loaded MCP admin routes');
} catch (error) {
  console.error('Error loading MCP admin routes:', error.message);
  // Create a dummy router to prevent app from crashing
  var mcpAdminRoutes = express.Router();
  mcpAdminRoutes.get('/', (req, res) => {
    res.status(500).send('MCP admin module not available');
  });
}

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});
const PORT = process.env.PORT || 3002;

// Import scanner utilities with socket.io support
const { generateConfig, runScan, generateReport } = require('./utils/scanner')(io);

// Import integrated scan flow utility with all functions
const integratedScanFlowModule = require('./utils/integrated-scan-flow');
const integratedScanFlow = integratedScanFlowModule(io);
const { runIntegratedScanFlow, generateReportFromEnhancedResults } = integratedScanFlow;

// Configure middleware
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'public')));

// Serve TinyMCE from node_modules
app.use('/tinymce', express.static(path.join(__dirname, 'node_modules', 'tinymce')));

// Serve reports directory
app.use('/reports', express.static(path.join(__dirname, '..', 'reports')));

// Configure Handlebars
app.engine('handlebars', engine({
  defaultLayout: 'main',
  layoutsDir: path.join(__dirname, 'views/layouts'),
  helpers: {
    json: function(context) {
      return JSON.stringify(context);
    },
    eq: function(a, b) {
      return a === b;
    },
    gt: function(a, b) {
      return a > b;
    },
    lt: function(a, b) {
      return a < b;
    },
    add: function(a, b) {
      return parseInt(a) + parseInt(b);
    },
    subtract: function(a, b) {
      return parseInt(a) - parseInt(b);
    },
    math: function(lvalue, operator, rvalue) {
      lvalue = parseFloat(lvalue);
      rvalue = parseFloat(rvalue);
      return {
        '+': lvalue + rvalue,
        '-': lvalue - rvalue,
        '*': lvalue * rvalue,
        '/': lvalue / rvalue,
        '%': lvalue % rvalue
      }[operator];
    },
    range: function(start, end) {
      const result = [];
      // Limit the number of pages shown to avoid performance issues
      const maxPages = 10;
      
      if (end - start > maxPages) {
        // If we have too many pages, show a subset around the current page
        const middle = Math.floor((start + end) / 2);
        const halfMax = Math.floor(maxPages / 2);
        
        // Adjust start and end to show pages around the middle
        start = Math.max(start, middle - halfMax);
        end = Math.min(end, middle + halfMax);
      }
      
      for (let i = start; i <= end; i++) {
        result.push(i);
      }
      return result;
    },
    objectSize: function(obj) {
      return Object.keys(obj).length;
    },
    formatDate: function(timestamp) {
      if (!timestamp) return 'Unknown';
      const date = new Date(parseInt(timestamp));
      return date.toLocaleString();
    },
    severityClass: function(severity) {
      const classes = {
        'Critical': 'danger',
        'High': 'danger',
        'Medium': 'warning',
        'Low': 'info',
        'Info': 'secondary'
      };
      return classes[severity] || 'secondary';
    }
  }
}));
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views'));

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, path.join(__dirname, '../swagger'));
  },
  filename: function(req, file, cb) {
    // Use the original filename
    cb(null, file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  fileFilter: function(req, file, cb) {
    // Accept only JSON and YAML files
    if (file.mimetype === 'application/json' || 
        file.originalname.endsWith('.yaml') || 
        file.originalname.endsWith('.yml')) {
      cb(null, true);
    } else {
      cb(new Error('Only JSON and YAML files are allowed'));
    }
  }
});

// Helper function to generate a config name from title
function generateConfigName(title) {
  // Remove special characters and convert to lowercase
  let configName = title.toLowerCase()
    .replace(/[^\w\s]/gi, '')
    .replace(/\s+/g, '_');
  
  // Remove filler words
  const fillerWords = ['a', 'an', 'the', 'and', 'or', 'but', 'for', 'nor', 'on', 'at', 'to', 'by', 'in'];
  let words = configName.split('_');
  words = words.filter(word => !fillerWords.includes(word));
  
  // Join the remaining words
  configName = words.join('_');
  
  return configName;
}

// Import scan metadata sync utility
const scanMetadataSync = require('./utils/scan-metadata-sync');

// Register routes
app.use('/report-editor', reportEditorRoutes);
app.use('/scan/api', scanRoutes(io));
app.use('/admin/prompts', adminPromptsRoutes);
app.use('/api/mcp', mcpRoutes);
app.use('/admin/mcp', mcpAdminRoutes);

// Routes


app.get('/', (req, res) => {
  res.render('index', {
    title: 'API Security Scanner',
    activeTab: 'home'
  });
});

// MCP Demo page
app.get('/mcp-demo', (req, res) => {
  res.render('mcp_demo', {
    title: 'MCP Demo',
    activeTab: 'mcp-demo'
  });
});

// Dashboard route for scan results
app.get('/dashboard', async (req, res) => {
  try {
    // Get pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    
    // Extract search filters from query parameters
    const filters = {
      query: req.query.query || '',
      enhanced: req.query.enhanced || '',
      severity: req.query.severity || '',
      dateFrom: req.query.dateFrom || '',
      dateTo: req.query.dateTo || ''
    };
    
    // Get filtered scans with metadata
    let scans;
    if (Object.values(filters).some(val => val !== '')) {
      // If any filter is applied, use the search function
      scans = await scanMetadataSync.searchScans(filters, limit, offset);
    } else {
      // Otherwise, get all scans without filtering
      scans = await scanMetadataSync.getAllScansWithMetadata(limit, offset);
    }
    
    // Render the dashboard
    res.render('dashboard', {
      title: 'Scan Results Dashboard',
      activeTab: 'dashboard',
      scans,
      // Pass filter values back to the template for form persistence
      query: filters.query,
      enhanced: filters.enhanced,
      severity: filters.severity,
      dateFrom: filters.dateFrom,
      dateTo: filters.dateTo,
      pagination: {
        page,
        limit,
        hasMore: scans.length === limit // Simple way to check if there might be more
      }
    });
  } catch (error) {
    console.error(`Error loading dashboard: ${error.message}`);
    res.render('error', {
      title: 'Error',
      message: 'Failed to load dashboard',
      error: error.message
    });
  }
});

// API endpoint to sync scan metadata
app.post('/api/sync-metadata', async (req, res) => {
  try {
    const result = await scanMetadataSync.syncFromFilesystemToRedis();
    res.json(result);
  } catch (error) {
    console.error(`Error syncing metadata: ${error.message}`);
    res.status(500).json({
      success: false,
      message: `Error: ${error.message}`
    });
  }
});

// Route to view detailed scan information
app.get('/dashboard/scan/:scanId', async (req, res) => {
  try {
    const { scanId } = req.params;
    
    // Get detailed scan information
    const scanDetails = await scanMetadataSync.getScanDetails(scanId);
    
    if (!scanDetails) {
      return res.status(404).render('error', {
        title: 'Scan Not Found',
        message: `Scan with ID ${scanId} not found`,
        error: 'The requested scan does not exist or has been deleted.'
      });
    }
    
    // Render the scan details page
    res.render('scan-details', {
      title: `Scan Details: ${scanDetails.title || scanId}`,
      activeTab: 'dashboard',
      scanDetails,
      enhancementOptions: {
        providers: [
          { id: 'openai', name: 'OpenAI' },
          { id: 'ollama', name: 'Ollama (Local)' }
        ],
        models: {
          openai: [
            { id: 'gpt-4o', name: 'GPT-4o' },
            { id: 'gpt-4-turbo', name: 'GPT-4 Turbo' },
            { id: 'gpt-3.5-turbo', name: 'GPT-3.5 Turbo' }
          ],
          ollama: [
            { id: 'llama3.3', name: 'Llama 3.3 (8B)' },
            { id: 'llama3', name: 'Llama 3 (70B)' },
            { id: 'mistral', name: 'Mistral' }
          ]
        }
      }
    });
  } catch (error) {
    console.error(`Error loading scan details: ${error.message}`);
    res.status(500).render('error', {
      title: 'Error',
      message: 'Failed to load scan details',
      error: error.message
    });
  }
});

// API endpoint to download scan results in JSON format
app.get('/api/results/:scanId/download', async (req, res) => {
  try {
    const { scanId } = req.params;
    const { enhanced } = req.query;
    
    // Get scan details to check if files exist
    const scanDetails = await scanMetadataSync.getScanDetails(scanId);
    
    if (!scanDetails) {
      return res.status(404).json({
        success: false,
        message: `Scan with ID ${scanId} not found`
      });
    }
    
    // Determine which file to download (enhanced or original)
    const filePath = enhanced === 'true' && scanDetails.hasEnhancedResults
      ? scanDetails.enhancedResultsPath
      : scanDetails.resultsPath;
    
    if (!filePath || !fs.existsSync(filePath)) {
      return res.status(404).json({
        success: false,
        message: `Results file not found for scan ${scanId}`
      });
    }
    
    // Set filename for download
    const filename = enhanced === 'true'
      ? `${scanId}_enhanced_results.json`
      : `${scanId}_results.json`;
    
    // Send the file
    res.download(filePath, filename);
  } catch (error) {
    console.error(`Error downloading results for ${req.params.scanId}: ${error.message}`);
    res.status(500).json({
      success: false,
      message: `Error: ${error.message}`
    });
  }
});

// API endpoint to delete a scan and all associated files
app.post('/api/scans/:scanId', async (req, res) => {
  // Check if this is a DELETE request via method override
  if (req.body._method !== 'DELETE') {
    return res.status(400).json({
      success: false,
      message: 'Invalid request method'
    });
  }
  
  try {
    const { scanId } = req.params;
    
    // Get scan details to check if files exist
    const scanDetails = await scanMetadataSync.getScanDetails(scanId);
    
    if (!scanDetails) {
      return res.status(404).json({
        success: false,
        message: `Scan with ID ${scanId} not found`
      });
    }
    
    // Delete all files associated with this scan
    let filesToDelete = [
      scanDetails.resultsPath,
      scanDetails.enhancedResultsPath,
      scanDetails.reportPath
    ].filter(Boolean); // Filter out null/undefined values
    
    // Add all result and report files found
    if (scanDetails.allResultFiles && Array.isArray(scanDetails.allResultFiles)) {
      filesToDelete = [...filesToDelete, ...scanDetails.allResultFiles];
    }
    
    if (scanDetails.allReportFiles && Array.isArray(scanDetails.allReportFiles)) {
      filesToDelete = [...filesToDelete, ...scanDetails.allReportFiles];
    }
    
    // Remove duplicates
    filesToDelete = [...new Set(filesToDelete)];
    
    let deletedCount = 0;
    let deletedFiles = [];
    
    for (const filePath of filesToDelete) {
      if (fs.existsSync(filePath)) {
        try {
          fs.unlinkSync(filePath);
          deletedCount++;
          deletedFiles.push(path.basename(filePath));
          console.log(`Deleted file: ${filePath}`);
        } catch (error) {
          console.error(`Error deleting file ${filePath}: ${error.message}`);
        }
      }
    }
    
    // Delete Redis keys associated with this scan
    try {
      // 1. Delete report cache (including vulnerability data)
      // This now handles its own connection check
      await redis.clearReportCache(scanId);
      
      // 2. Ensure Redis is connected before proceeding with other deletions
      if (redis.ensureConnection && typeof redis.ensureConnection === 'function') {
        // Use the new ensureConnection function if available
        await redis.ensureConnection();
      }
      
      // 3. Delete any scan-specific vulnerability data
      if (redis.client && redis.client.isOpen) {
        // Get all vulnerability-related keys for this scan
        const vulnKeys = await redis.client.keys(`*:${scanId}:*`);
        console.log(`Found ${vulnKeys.length} additional Redis keys for scan ID: ${scanId}`);
        
        if (vulnKeys.length > 0) {
          // Use pipeline for better performance
          const pipeline = redis.client.multi();
          for (const key of vulnKeys) {
            pipeline.del(key);
          }
          await pipeline.exec();
          console.log(`Successfully deleted ${vulnKeys.length} additional Redis keys for scan ID: ${scanId}`);
        }
        
        // 4. Delete metadata
        const metadataKey = `scan:${scanId}:metadata`;
        await redis.client.del(metadataKey);
        
        // 5. Remove from scans sorted set
        await redis.client.zRem('scans', scanId);
      } else {
        console.warn('Redis client not available or not connected, skipping metadata deletion');
      }
    } catch (redisError) {
      console.error(`Error deleting Redis keys: ${redisError.message}`);
      // Continue with the response even if Redis operations fail
    }
    
    // Return success response
    return res.status(200).json({
      success: true,
      message: `Scan ${scanId} and ${deletedCount} associated files have been deleted.`,
      deletedFiles: deletedFiles
    });
  } catch (error) {
    console.error(`Error deleting scan ${req.params.scanId}: ${error.message}`);
    console.error(error.stack);
    
    // Return error response
    return res.status(500).json({
      success: false,
      message: `Error deleting scan: ${error.message}`
    });
  }
});

app.get('/scan', async (req, res) => {
  try {
    // Get list of config files
    const configDir = path.join(__dirname, '..', 'configs');
    let configs = [];
    
    if (fs.existsSync(configDir)) {
      const files = fs.readdirSync(configDir)
        .filter(file => file.endsWith('.yaml') || file.endsWith('.yml'))
        .sort();
      
      configs = files.map(file => ({
        name: file,
        path: path.join('configs', file)
      }));
    }
    
    res.render('scan', {
      title: 'API Security Scan',
      activeTab: 'scan',
      configs
    });
  } catch (error) {
    console.error('Error rendering scan page:', error);
    res.status(500).send('Error loading scan page');
  }
});

app.post('/scan', upload.single('swaggerFile'), async (req, res) => {
  // Extract form data
  const { 
    title, 
    description, 
    targetUrl, 
    allowDos, 
    sqlInjection, 
    useLlmEnhancement, 
    llmProvider, 
    llmModel, 
    sessionId 
  } = req.body;
  
  if (!req.file) {
    if (sessionId) {
      // For AJAX requests, return JSON error
      return res.status(400).json({
        success: false,
        error: 'Please upload a Swagger/OpenAPI file'
      });
    } else {
      // For regular form submissions, render the page with error
      return res.render('scan', {
        title: 'Scan Target',
        activeTab: 'scan',
        error: 'Please upload a Swagger/OpenAPI file'
      });
    }
  }
  
  if (!title || !targetUrl) {
    if (sessionId) {
      // For AJAX requests, return JSON error
      return res.status(400).json({
        success: false,
        error: 'Title and Target URL are required'
      });
    } else {
      // For regular form submissions, render the page with error
      return res.render('scan', {
        title: 'Scan Target',
        activeTab: 'scan',
        error: 'Title and Target URL are required'
      });
    }
  }
  
  try {
    // Generate config name from title
    const configName = generateConfigName(title);
    const swaggerPath = path.join(__dirname, '../swagger', req.file.filename);
    
    // If this is a socket.io request, send initial response and process asynchronously
    if (sessionId) {
      // Send initial response to client
      res.json({
        success: true,
        message: 'Scan started',
        sessionId
      });
      
      // Process the scan asynchronously using the integrated scan flow
      (async () => {
        try {
          // Generate config YAML using gen_config_yaml.py
          await generateConfig(swaggerPath, configName, sessionId);
          
          // Get the config path - use absolute path to ensure it's found
          const configPath = path.join(__dirname, '..', 'configs', `${configName}.yaml`);
          
          // Determine if we should use LLM enhancement
          const shouldEnhance = useLlmEnhancement === 'on' || useLlmEnhancement === true;
          
          // Set up options for the integrated scan flow
          const scanOptions = {
            configPath,
            targetUrl,
            allowDos: allowDos === 'true' || allowDos === true,
            sqlInjection: sqlInjection || 'smart',
            sessionId
          };
          
          // Add LLM options if enhancement is enabled
          if (shouldEnhance) {
            scanOptions.llmProvider = llmProvider || 'openai';
            scanOptions.llmModel = llmModel || 'gpt-4o';
          } else {
            // Skip LLM enhancement
            scanOptions.skipEnhancement = true;
          }
          
          // Run the integrated scan flow
          const { scanId } = await runIntegratedScanFlow(scanOptions, io);
          
          // Store scan info in app.locals for results page
          app.locals.scans = app.locals.scans || {};
          app.locals.scans[scanId] = {
            id: scanId,
            title,
            description,
            timestamp: new Date().toISOString(),
            enhanced: shouldEnhance
          };
          
          // Emit completion event
          io.to(sessionId).emit('scan-complete', {
            success: true,
            scanId,
            redirectUrl: `/results/${scanId}`
          });
        } catch (error) {
          console.error(`Error during scan process: ${error.message}`);
          
          // Emit error event
          io.to(sessionId).emit('scan-error', {
            success: false,
            error: error.message
          });
        }
      })();
    } else {
      // For regular form submissions, process synchronously
      // Generate config YAML using gen_config_yaml.py
      await generateConfig(swaggerPath, configName);
      
      // Get the config path - use absolute path to ensure it's found
      const configPath = path.join(__dirname, '..', 'configs', `${configName}.yaml`);
      
      // Determine if we should use LLM enhancement
      const shouldEnhance = useLlmEnhancement === 'on' || useLlmEnhancement === true;
      
      // Set up options for the integrated scan flow
      const scanOptions = {
        configPath,
        targetUrl,
        allowDos: allowDos === 'true' || allowDos === true,
        sqlInjection: sqlInjection || 'smart'
      };
      
      // Add LLM options if enhancement is enabled
      if (shouldEnhance) {
        scanOptions.llmProvider = llmProvider || 'openai';
        scanOptions.llmModel = llmModel || 'gpt-4o';
      } else {
        // Skip LLM enhancement
        scanOptions.skipEnhancement = true;
      }
      
      // Run the integrated scan flow (without session ID for synchronous operation)
      const { scanId } = await runIntegratedScanFlow(scanOptions);
      
      // Store scan info in app.locals
      app.locals.scans = app.locals.scans || {};
      app.locals.scans[scanId] = {
        id: scanId,
        title,
        description,
        timestamp: new Date().toISOString(),
        enhanced: shouldEnhance
      };
      
      // Redirect to the results page
      res.redirect(`/results/${scanId}?title=${encodeURIComponent(title)}&description=${encodeURIComponent(description)}`);
    }
  } catch (error) {
    console.error(`Error during scan process: ${error.message}`);
    
    if (sessionId) {
      // For AJAX requests, return JSON error
      return res.status(500).json({
        success: false,
        error: error.message
      });
    } else {
      // For regular form submissions, render the page with error
      return res.render('scan', {
        title: 'Scan Target',
        activeTab: 'scan',
        error: error.message
      });
    }
  }
});

app.get('/results/:scanId', redisSyncMiddleware.expressScanIdMiddleware, async (req, res) => {
  const { scanId } = req.params;
  const { title, description } = req.query;
  
  // Check if we have scan info in app.locals
  const scanInfo = app.locals.scans && app.locals.scans[scanId];
  const scanTitle = scanInfo ? scanInfo.title : (title || 'Untitled Scan');
  const scanDescription = scanInfo ? scanInfo.description : (description || '');
  
  // Try multiple possible report paths
  const possibleReportPaths = [
    path.join(__dirname, '..', 'reports', `report_${scanId}.html`),
    path.join(__dirname, '..', 'reports', `report_${scanId.replace(/^report_/, '')}.html`),
  ];
  
  // Also check the reports directory for any files that might match this scan ID
  const reportsDir = path.join(__dirname, '..', 'reports');
  let reportFound = false;
  let reportPath = null;
  
  // First try the expected paths
  for (const testPath of possibleReportPaths) {
    if (fs.existsSync(testPath)) {
      reportPath = testPath;
      reportFound = true;
      break;
    }
  }
  
  // If not found, try to find the most recent report file
  if (!reportFound && fs.existsSync(reportsDir)) {
    try {
      const files = fs.readdirSync(reportsDir)
        .filter(file => file.endsWith('.html'))
        .sort((a, b) => {
          const statA = fs.statSync(path.join(reportsDir, a));
          const statB = fs.statSync(path.join(reportsDir, b));
          return statB.mtime.getTime() - statA.mtime.getTime(); // Sort by modification time, newest first
        });
      
      if (files.length > 0) {
        reportPath = path.join(reportsDir, files[0]);
        reportFound = true;
        console.log(`Using most recent report file: ${files[0]}`);
      }
    } catch (error) {
      console.error(`Error finding report files: ${error.message}`);
    }
  }
  
  if (!reportFound) {
    return res.render('error', {
      title: 'Error',
      message: `Report for scan ID ${scanId} not found`
    });
  }
  
  // Get structured vulnerability data from Redis or parse from files
  let vulnerabilities = [];
  let reportContent = '';
  
  try {
    // First, check if we have complete vulnerability data in Redis
    console.log(`Checking for cached vulnerability data for scan ID: ${scanId}`);
    const cachedData = await redis.getCachedReportField(scanId, 'complete_vulnerability_data');
    
    if (cachedData) {
      try {
        // Parse the cached data
        vulnerabilities = JSON.parse(cachedData);
        console.log(`Loaded ${vulnerabilities.length} vulnerabilities from Redis cache for view page`);
      } catch (parseError) {
        console.error(`Error parsing cached vulnerability data: ${parseError.message}`);
        // Continue with other methods if parsing fails
      }
    }
    
    // If no cached data, check for backup file
    if (vulnerabilities.length === 0) {
      const backupPath = path.join(__dirname, '..', 'results', `${scanId}_backup.json`);
      if (fs.existsSync(backupPath)) {
        try {
          const backupData = JSON.parse(fs.readFileSync(backupPath, 'utf8'));
          if (backupData.vulnerabilities && Array.isArray(backupData.vulnerabilities)) {
            vulnerabilities = backupData.vulnerabilities;
            console.log(`Loaded ${vulnerabilities.length} vulnerabilities from backup file for view page`);
          }
        } catch (backupError) {
          console.error(`Error loading backup data: ${backupError.message}`);
          // Continue with other methods if backup loading fails
        }
      }
    }
    
    // If still no vulnerabilities, try parsing JSON results
    if (vulnerabilities.length === 0) {
      console.log(`Getting vulnerabilities from JSON results for scan ID: ${scanId} for view page`);
      vulnerabilities = await parseResultsJson(scanId);
      console.log(`Extracted ${vulnerabilities.length} vulnerabilities from JSON results for view page`);
    }
    
    // If still no vulnerabilities, fall back to HTML parsing as a last resort
    if (vulnerabilities.length === 0 && reportPath) {
      console.log(`No vulnerabilities found in previous methods, falling back to HTML parsing for view page`);
      reportContent = fs.readFileSync(reportPath, 'utf8');
      vulnerabilities = parseReportHtml(reportContent);
      console.log(`Extracted ${vulnerabilities.length} vulnerabilities from HTML report as fallback for view page`);
    }
    
    // If we still have no vulnerabilities and no report content, read the report file
    if (vulnerabilities.length === 0 && reportContent === '') {
      reportContent = fs.readFileSync(reportPath, 'utf8');
    }
    
    // Ensure all vulnerabilities have the required fields
    vulnerabilities = vulnerabilities.map(vuln => ({
      id: vuln.id || 'unknown',
      name: vuln.name || 'Unnamed Vulnerability',
      url: vuln.url || '',
      severity: vuln.severity || '',
      description: vuln.description || '',
      risk: vuln.risk || '',
      impact: vuln.impact || '',
      examples: vuln.examples || '',
      remediation: vuln.remediation || '',
      evidence: vuln.evidence || ''
    }));
    
    // Get scan metadata for additional details
    const scanMetadata = await redis.getScanMetadata(scanId);
    
    // Render the results page with structured vulnerability data
    res.render('results', {
      title: 'Scan Results',
      activeTab: 'results',
      scanId,
      scanTitle,
      scanDescription,
      vulnerabilities,
      reportContent,
      scanDetails: scanMetadata || {}
    });
  } catch (error) {
    console.error(`Error processing vulnerability data: ${error.message}`);
    
    // Fall back to just rendering the report content if there's an error
    try {
      reportContent = fs.readFileSync(reportPath, 'utf8');
      res.render('results', {
        title: 'Scan Results',
        activeTab: 'results',
        scanId,
        scanTitle,
        scanDescription,
        reportContent
      });
    } catch (readErr) {
      return res.render('error', {
        title: 'Error',
        message: `Error reading report: ${readErr.message}`
      });
    }
  }
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render('error', {
    title: 'Error',
    message: err.message || 'Something went wrong!'
  });
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('A client connected');
  
  // Handle joining a scan session
  socket.on('join-scan-session', (sessionId) => {
    console.log(`Client joined scan session: ${sessionId}`);
    socket.join(sessionId);
    
    // Send current session state to the client if it exists
    const sessionData = getSession(sessionId);
    if (sessionData) {
      console.log(`Sending session state for ${sessionId}`);
      socket.emit('scan-session-state', sessionData);
    }
  });
  
  // Handle joining a section enhancement session
  socket.on('join-session', (sessionId) => {
    console.log(`Client joined enhancement session: ${sessionId}`);
    socket.join(sessionId);
    
    // Send current session state to the client if it exists
    const sessionData = getSession(sessionId);
    if (sessionData && sessionData.type === 'enhance-section') {
      socket.emit('enhancement-status', {
        sessionId,
        status: sessionData.paused ? 'paused' : 'running',
        startTime: sessionData.startTime,
        output: sessionData.output || ''
      });
    }
  });
  
  // Handle leaving a session
  socket.on('leave-session', (sessionId) => {
    console.log(`Client left session: ${sessionId}`);
    socket.leave(sessionId);
  });
  
  // Handle pause scan request
  socket.on('pause-scan', (sessionId) => {
    console.log(`Request to pause scan: ${sessionId}`);
    const success = scanner.pauseScan(sessionId);
    socket.emit('scan-control-response', {
      action: 'pause',
      success,
      message: success ? 'Scan paused successfully' : 'Failed to pause scan'
    });
  });
  
  // Handle resume scan request
  socket.on('resume-scan', (sessionId) => {
    console.log(`Request to resume scan: ${sessionId}`);
    const success = scanner.resumeScan(sessionId);
    socket.emit('scan-control-response', {
      action: 'resume',
      success,
      message: success ? 'Scan resumed successfully' : 'Failed to resume scan'
    });
  });
  
  // Handle stop scan request
  socket.on('stop-scan', (data) => {
    const sessionId = typeof data === 'object' ? data.sessionId : data;
    console.log(`Request to stop scan: ${sessionId}`);
    
    // Send immediate feedback to the client
    io.to(sessionId).emit('scanner-output', {
      type: 'scan',
      data: '\n[System] Stopping scan as requested by user...\n'
    });
    
    // Try to stop the scan using the scanner utility
    const success = scanner.stopScan(sessionId);
    
    // Send the response to all clients in the session room
    io.to(sessionId).emit('scan-control-response', {
      action: 'stop',
      success,
      message: success ? 'Scan stopped successfully' : 'Failed to stop scan'
    });
    
    // If successful, update the UI to reflect the stopped state
    if (success) {
      io.to(sessionId).emit('scanner-status', {
        type: 'scan-stopped',
        success: true
      });
      
      // Add additional output to show the scan was stopped
      io.to(sessionId).emit('scanner-output', {
        type: 'scan',
        data: '\n[System] Scan has been stopped successfully.\n'
      });
    }
  });
  
  socket.on('disconnect', () => {
    console.log('A client disconnected');
  });
});

// Helper function to parse HTML report and extract vulnerability data
/**
 * Parse vulnerabilities from JSON results file
 * @param {string} scanId - The scan ID
 * @returns {Array} - Array of vulnerability objects
 */
async function parseResultsJson(scanId) {
  console.log(`Parsing JSON results for scan ID: ${scanId}`);
  const vulnerabilities = [];
  
  try {
    // Define paths for both regular and enhanced results files
    const resultsDir = path.join(__dirname, '..', 'results');
    const resultFiles = fs.readdirSync(resultsDir);
    
    // Try to find the most appropriate JSON file for this scan ID
    let jsonPath = null;
    
    // First look for enhanced results with the scan ID
    const enhancedPatterns = [
      `${scanId}_enhanced.json`,
      `enhanced_${scanId}.json`,
      `enhanced_${scanId}_description_enhanced.json`
    ];
    
    // Try exact matches with common patterns first
    for (const pattern of enhancedPatterns) {
      const testPath = path.join(resultsDir, pattern);
      if (fs.existsSync(testPath)) {
        jsonPath = testPath;
        console.log(`Found enhanced results with exact pattern: ${jsonPath}`);
        break;
      }
    }
    
    // If no enhanced file found, try regex pattern
    if (!jsonPath) {
      const enhancedRegex = new RegExp(`.*${scanId}.*(?:enhanced|llm).*\.json$`);
      for (const file of resultFiles) {
        if (enhancedRegex.test(file)) {
          jsonPath = path.join(resultsDir, file);
          console.log(`Found enhanced results matching regex: ${jsonPath}`);
          break;
        }
      }
    }
    
    // If still no match, try the regular results file
    if (!jsonPath) {
      const regularPath = path.join(resultsDir, `${scanId}.json`);
      if (fs.existsSync(regularPath)) {
        jsonPath = regularPath;
        console.log(`Found regular results file: ${jsonPath}`);
      } else {
        // Last resort: try any JSON file with the scanId
        for (const file of resultFiles) {
          if (file.includes(scanId) && file.endsWith('.json')) {
            jsonPath = path.join(resultsDir, file);
            console.log(`Found JSON file containing scanId: ${jsonPath}`);
            break;
          }
        }
      }
    }
    
    // If no JSON file found, return empty array
    if (!jsonPath || !fs.existsSync(jsonPath)) {
      console.error(`No JSON results file found for scan ID: ${scanId}`);
      return [];
    }
    
    console.log(`Reading JSON results from: ${jsonPath}`);
    const jsonContent = fs.readFileSync(jsonPath, 'utf8');
    const results = JSON.parse(jsonContent);
    
    // Extract vulnerabilities from scanners with findings
    if (results.scanners && Array.isArray(results.scanners)) {
      console.log(`Found ${results.scanners.length} scanners in results`);
      
      // Process each scanner's findings
      for (const scanner of results.scanners) {
        if (scanner.findings && Array.isArray(scanner.findings) && scanner.findings.length > 0) {
          console.log(`Found ${scanner.findings.length} findings in scanner: ${scanner.name}`);
          
          // Process each finding as a vulnerability
          for (const finding of scanner.findings) {
            // Generate a unique ID based on the vulnerability name
            const name = finding.vulnerability;
            const id = name.toLowerCase().replace(/[^a-z0-9]/g, '_');
            const severity = finding.severity || 'MEDIUM';
            const url = finding.endpoint || '';
            
            // Get cached edited fields from Redis if they exist
            const cachedUrl = await redis.getCachedReportField(scanId, `${id}_url`);
            const cachedSeverity = await redis.getCachedReportField(scanId, `${id}_severity`);
            const cachedDescription = await redis.getCachedReportField(scanId, `${id}_description`);
            const cachedRisk = await redis.getCachedReportField(scanId, `${id}_risk`);
            const cachedImpact = await redis.getCachedReportField(scanId, `${id}_impact`);
            const cachedExamples = await redis.getCachedReportField(scanId, `${id}_examples`);
            const cachedRemediation = await redis.getCachedReportField(scanId, `${id}_remediation`);
            
            // Extract additional fields from metadata if available (for enhanced results)
            let risk = '';
            let impact = '';
            let examples = '';
            let remediation = '';
            
            // Check for direct remediation field (new format)
            if (finding.remediation) {
              remediation = finding.remediation;
            }
            
            // Check for direct enhanced fields (newest format)
            if (finding.risk_assessment) {
              risk = finding.risk_assessment;
            }
            
            if (finding.impact_analysis) {
              impact = finding.impact_analysis;
            }
            
            if (finding.real_world_examples) {
              examples = finding.real_world_examples;
            }
            
            // Try to extract other fields from remediation if they're not in a separate field
            // This is a simple heuristic to extract sections from the LLM-generated content
            if (!risk && !finding.metadata) {
              const riskMatch = remediation.match(/(?:Root Cause Analysis|Risk):\s*([\s\S]*?)(?:\n\n\d\.\s|$)/i);
              if (riskMatch && riskMatch[1]) risk = riskMatch[1].trim();
            }
            
            if (!impact && !finding.metadata) {
              const impactMatch = remediation.match(/(?:Impact|Business Impact):\s*([\s\S]*?)(?:\n\n\d\.\s|$)/i);
              if (impactMatch && impactMatch[1]) impact = impactMatch[1].trim();
            }
            
            if (!examples && !finding.metadata) {
              const examplesMatch = remediation.match(/(?:Examples|Code Examples|Real-World Examples):\s*([\s\S]*?)(?:\n\n\d\.\s|$)/i);
              if (examplesMatch && examplesMatch[1]) examples = examplesMatch[1].trim();
            }
            
            // Also check metadata object (old format)
            if (finding.metadata) {
              risk = finding.metadata.risk || risk;
              impact = finding.metadata.impact || impact;
              examples = finding.metadata.examples || examples;
              remediation = finding.metadata.remediation || remediation;
            }
            
            // Use cached values if available, otherwise use the finding details and metadata
            vulnerabilities.push({
              id,
              name,
              url: cachedUrl || url,
              severity: cachedSeverity || severity,
              description: cachedDescription || finding.details || '',
              risk: cachedRisk || risk,
              impact: cachedImpact || impact,
              examples: cachedExamples || examples,
              remediation: cachedRemediation || remediation,
              evidence: JSON.stringify(finding.evidence || {}, null, 2)
            });
            
            console.log(`Added vulnerability: ${name} (${severity}) - ${url}`);
          }
        }
      }
    }
    
    console.log(`Extracted ${vulnerabilities.length} vulnerabilities from JSON results`);
    return vulnerabilities;
  } catch (error) {
    console.error(`Error parsing JSON results: ${error.message}`);
    console.error(error.stack);
    return [];
  }
}

function parseReportHtml(htmlContent) {
  console.log('Parsing HTML report for vulnerabilities');
  const vulnerabilities = [];
  
  try {
    // Check if the HTML is empty or invalid
    if (!htmlContent || typeof htmlContent !== 'string' || htmlContent.trim() === '') {
      console.error('HTML content is empty or invalid');
      return [];
    }
    
    // First try to parse the new report format with vulnerability divs and vuln-header
    const vulnDivRegex = /<div class="vulnerability[^"]*">\s*<div class="vuln-header">\s*<h3>([^<]+)<\/h3>[\s\S]*?(?=<div class="vulnerability|$)/g;
    let match;
    let vulnCount = 0;
    
    while ((match = vulnDivRegex.exec(htmlContent)) !== null) {
      vulnCount++;
      // Extract the vulnerability name, removing any numbering prefix (e.g., "1. JWT 'none' Algorithm Vulnerability" -> "JWT 'none' Algorithm Vulnerability")
      const fullName = match[1].trim();
      const name = fullName.replace(/^\d+\.\s*/, '');
      const content = match[0]; // The entire vulnerability div content
      
      console.log(`Found vulnerability section: ${name}`);
      
      // Helper function to extract content from a section with a specific class
      const extractSectionByClass = (sectionClass) => {
        // The regex pattern needs to be more flexible to handle different whitespace patterns
        const regex = new RegExp(`<div class="section">\s*<div class="section-title">${sectionClass}:<\/div>\s*<div>([\s\S]*?)<\/div>\s*<\/div>`, 'i');
        const sectionMatch = content.match(regex);
        if (sectionMatch && sectionMatch[1]) {
          console.log(`Found ${sectionClass} section: ${sectionMatch[1].substring(0, 50)}...`);
          return sectionMatch[1].trim();
        }
        return '';
      };
      
      // Extract the severity from the span with class="severity"
      const severityMatch = content.match(/<span class="severity[^"]*">([^<]+)<\/span>/);
      const severity = severityMatch ? severityMatch[1].trim() : '';
      
      // Extract Endpoint/URL with a more specific regex pattern
      let url = '';
      // Try to find Endpoint first
      const endpointRegex = /<div class="section">\s*<div class="section-title">Endpoint:<\/div>\s*<div>([^<]+)<\/div>/i;
      const endpointMatch = content.match(endpointRegex);
      if (endpointMatch && endpointMatch[1]) {
        url = endpointMatch[1].trim();
        console.log(`Found Endpoint: ${url}`);
      } else {
        // Fall back to URL if Endpoint not found (for backward compatibility)
        const urlRegex = /<div class="section">\s*<div class="section-title">URL:<\/div>\s*<div>([^<]+)<\/div>/i;
        const urlMatch = content.match(urlRegex);
        if (urlMatch && urlMatch[1]) {
          url = urlMatch[1].trim();
          console.log(`Found URL (legacy): ${url}`);
        }
      }
      
      // Extract other sections
      const description = extractSectionByClass('Description') || extractSectionByClass('Overview');
      const risk = extractSectionByClass('Risk Assessment') || extractSectionByClass('Risk');
      const impact = extractSectionByClass('Impact') || extractSectionByClass('Impact Analysis');
      const examples = extractSectionByClass('Examples') || extractSectionByClass('Real-World Examples');
      const remediation = extractSectionByClass('Remediation') || extractSectionByClass('Mitigation');
      const evidence = extractSectionByClass('Evidence') || extractSectionByClass('Proof of Concept');
      
      // Generate a unique ID based on the vulnerability name
      const id = name.toLowerCase().replace(/[^a-z0-9]/g, '_');
      
      vulnerabilities.push({
        id,
        name,
        url,
        severity,
        description,
        risk,
        impact,
        examples,
        remediation,
        evidence
      });
    }
    
    console.log(`Extracted ${vulnCount} vulnerabilities from the report`);
    
    // If no vulnerabilities were found but HTML content exists, try the original h2 pattern
    if (vulnerabilities.length === 0 && htmlContent.length > 0) {
      console.log('No vulnerabilities found with new pattern, trying original h2 pattern');
      
      // Try the original pattern with h2 tags
      const vulnSectionRegex = /<h2>([^<]+)<\/h2>([\s\S]*?)(?=<h2>|$)/g;
      while ((match = vulnSectionRegex.exec(htmlContent)) !== null) {
        vulnCount++;
        const name = match[1].trim();
        const content = match[2];
        
        console.log(`Found vulnerability section with h2 pattern: ${name}`);
        
        // Helper function to extract content between section headers
        const extractSection = (sectionName) => {
          const regex = new RegExp(`<h3>${sectionName}<\/h3>([\s\S]*?)(?=<h3>|$)`);
          const sectionMatch = content.match(regex);
          return sectionMatch ? sectionMatch[1].trim() : '';
        };
        
        // Extract various sections
        const description = extractSection('Description');
        const risk = extractSection('Risk Assessment');
        const impact = extractSection('Impact Analysis');
        const examples = extractSection('Real-World Examples');
        const remediation = extractSection('Remediation');
        const evidence = extractSection('Evidence');
        
        // Generate a unique ID based on the vulnerability name
        const id = name.toLowerCase().replace(/[^a-z0-9]/g, '_');
        
        vulnerabilities.push({
          id,
          name,
          description,
          risk,
          impact,
          examples,
          remediation,
          evidence
        });
      }
    }
    
    // If still no vulnerabilities found, try a more generic approach
    if (vulnerabilities.length === 0 && htmlContent.length > 0) {
      console.log('No vulnerabilities found with specific patterns, trying generic approach');
      
      // Look for any section that might contain vulnerability information
      // This is a more lenient approach for reports with different formatting
      const sections = htmlContent.split(/<h[1-4][^>]*>/);
      
      for (let i = 1; i < sections.length; i++) { // Start from 1 to skip the first split result
        const sectionTitle = sections[i-1].match(/<h[1-4][^>]*>([^<]+)<\/h[1-4]>/i);
        if (sectionTitle && sectionTitle[1]) {
          const name = sectionTitle[1].trim();
          const content = sections[i];
          
          // Skip if this looks like a general section, not a vulnerability
          if (['overview', 'summary', 'introduction', 'conclusion', 'table of contents'].includes(name.toLowerCase())) {
            continue;
          }
          
          console.log(`Found potential vulnerability section: ${name}`);
          
          vulnerabilities.push({
            id: name.toLowerCase().replace(/[^a-z0-9]/g, '_'),
            name,
            description: content.substring(0, 500), // Take first part as description
            risk: '',
            impact: '',
            examples: '',
            remediation: '',
            evidence: ''
          });
        }
      }
    }
    
    // If still no vulnerabilities found, create a placeholder for editing
    if (vulnerabilities.length === 0) {
      console.log('No vulnerabilities found, creating placeholder for editing');
      vulnerabilities.push({
        id: 'placeholder',
        name: 'Placeholder Vulnerability',
        description: 'No vulnerabilities were found in the report. You can edit this placeholder to add information.',
        risk: '',
        impact: '',
        examples: '',
        remediation: '',
        evidence: ''
      });
    }
  } catch (error) {
    console.error(`Error parsing HTML report: ${error.message}`);
    console.error(error.stack);
    
    // Return a placeholder in case of error
    return [{
      id: 'error',
      name: 'Error Parsing Report',
      description: `An error occurred while parsing the report: ${error.message}`,
      risk: '',
      impact: '',
      examples: '',
      remediation: '',
      evidence: ''
    }];
  }
  
  return vulnerabilities;
}

// Route to re-enhance a scan result with LLM
app.get('/results/:scanId/enhance', redisSyncMiddleware.expressScanIdMiddleware, (req, res) => {
  const { scanId } = req.params;
  
  // Render the re-enhance form
  res.render('enhance-report', {
    title: 'Enhance Report with LLM',
    activeTab: 'results',
    scanId
  });
});

// Route for the enhancement modal page
app.get('/results/:scanId/enhance', redisSyncMiddleware.expressScanIdMiddleware, async (req, res) => {
  const { scanId } = req.params;
  const { provider, model } = req.query;
  
  // Generate a unique session ID for socket communication
  const sessionId = `enhance_${scanId}_${Date.now()}`;
  
  try {
    // Get scan details to check if files exist
    const scanDetails = await scanMetadataSync.getScanDetails(scanId);
    
    if (!scanDetails || !scanDetails.hasResults) {
      return res.status(404).json({
        success: false,
        message: `Scan results not found for ID ${scanId}`
      });
    }
    
    // Check if scan was previously enhanced
    const wasEnhanced = scanDetails.enhanced || false;
    const previousProvider = scanDetails.llmProvider || 'unknown';
    const previousModel = scanDetails.llmModel || 'unknown';
    
    // Get vulnerability count if available
    let vulnCount = 0;
    try {
      const reportManager = require('./utils/report-manager');
      const vulnList = await reportManager.getVulnerabilityList(scanId);
      vulnCount = vulnList.length;
    } catch (err) {
      console.error(`Error getting vulnerability count: ${err.message}`);
    }
    
    // Render the enhancement modal page
    return res.render('enhance-modal', {
      layout: false,
      scanId,
      sessionId,
      provider: provider || 'openai',
      model: model || 'gpt-4o',
      wasEnhanced,
      previousProvider,
      previousModel,
      vulnCount
    });
  } catch (error) {
    console.error(`Error rendering enhancement modal: ${error.message}`);
    res.status(500).json({
      success: false,
      message: `Error: ${error.message}`
    });
  }
});

// Legacy POST endpoint for backward compatibility
app.post('/api/results/:scanId/enhance', redisSyncMiddleware.expressScanIdMiddleware, async (req, res) => {
  const { scanId } = req.params;
  const { provider, model } = req.body;
  
  // Redirect to the GET endpoint
  res.redirect(`/api/results/${scanId}/enhance?provider=${encodeURIComponent(provider || 'openai')}&model=${encodeURIComponent(model || 'gpt-4o')}`);
});

// API endpoint to start the enhancement process
app.post('/api/results/:scanId/enhance/start', redisSyncMiddleware.expressScanIdMiddleware, async (req, res) => {
  const { scanId } = req.params;
  const { provider, model, sessionId } = req.body;
  
  try {
    // Get scan details to check if files exist
    const scanDetails = await scanMetadataSync.getScanDetails(scanId);
    
    if (!scanDetails || !scanDetails.hasResults) {
      return res.status(404).json({
        success: false,
        message: `Scan results not found for ID ${scanId}`
      });
    }
    
    // Send initial response to client
    res.json({
      success: true,
      message: 'Enhancement process started',
      sessionId,
      scanId
    });
    
    // Process the enhancement asynchronously
    (async () => {
      try {
        // Define input and output paths
        const inputPath = scanDetails.resultsPath;
        const outputPath = path.join(__dirname, '..', 'results', `${scanId}_enhanced.json`);
        const reportPath = path.join(__dirname, '..', 'reports', `report_${scanId}.html`);
        
        // Build the command arguments based on the memory about report_generator.py
        // Use the full path to report_generator.py to ensure it's found
        const reportGeneratorPath = path.join(__dirname, '..', 'report_generator.py');
        const args = [
          reportGeneratorPath,
          'enhance-with-llm',
          '--input', inputPath,
          '--output', outputPath,
          '--provider', provider,
          '--model', model
          // Removed report generation flags to prevent double processing
          // The web interface will generate the report after enhancement
        ];
        
        // If using OpenAI, pass the API key from environment variable
        if (provider === 'openai') {
          const apiKey = process.env.LLM_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
          if (apiKey) {
            args.push('--api-key', apiKey);
          }
        }
        
        // Start the process
        // Execute python3 with the full path to the script
        // Don't use cd in the command, use the absolute path to the script and set the correct working directory
        console.log(`Running command: python3 ${args.join(' ')}`);
        
        // Use the root directory as cwd to ensure the script is found
        const rootDir = path.join(__dirname, '..');
        console.log(`Using working directory: ${rootDir}`);
        
        const pythonProcess = spawn('python3', args, { 
          cwd: rootDir,
          env: { ...process.env }
        });
        
        // Track the process if session ID is provided
        const { setSession, updateSessionStatus } = require('./utils/session-store');
        setSession(sessionId, {
          process: pythonProcess,
          type: 'enhance',
          startTime: Date.now(),
          paused: false,
          output: ''
        });
        
        let output = '';
        
        pythonProcess.stdout.on('data', (data) => {
          const chunk = data.toString();
          output += chunk;
          console.log(chunk);
          
          // Check for progress information in the output
          // Try multiple patterns to match different output formats
          let progressMatch = chunk.match(/Processing vulnerability (\d+) of (\d+)/i);
          if (!progressMatch) {
            progressMatch = chunk.match(/Processing item (\d+)\/(\d+)/i);
          }
          if (!progressMatch) {
            progressMatch = chunk.match(/Enhancing vulnerability (\d+) of (\d+)/i);
          }
          if (!progressMatch) {
            progressMatch = chunk.match(/Progress: (\d+)\/(\d+) \((\d+\.\d+)%\)/i);
            if (progressMatch) {
              // Format is different, we have current, total, and percentage directly
              const current = parseInt(progressMatch[1]);
              const total = parseInt(progressMatch[2]);
              const percentage = parseFloat(progressMatch[3]);
              
              // Emit progress update
              io.to(sessionId).emit('enhancement-progress', {
                current,
                total,
                percentage
              });
              
              // Skip the regular progress calculation below
              progressMatch = null;
            }
          }
          if (!progressMatch) {
            progressMatch = chunk.match(/Processing batch (\d+)\/(\d+)/i);
          }
          if (progressMatch) {
            const current = parseInt(progressMatch[1]);
            const total = parseInt(progressMatch[2]);
            const percentage = Math.round((current / total) * 100);
            
            // Emit progress update
            io.to(sessionId).emit('enhancement-progress', {
              current,
              total,
              percentage
            });
          }
          
          // Emit to specific session
          io.to(sessionId).emit('scanner-output', {
            type: 'enhance',
            data: chunk
          });
        });
        
        pythonProcess.stderr.on('data', (data) => {
          const chunk = data.toString();
          output += chunk;
          console.error(chunk);
          
          // Emit to specific session
          io.to(sessionId).emit('scanner-output', {
            type: 'enhance',
            data: chunk,
            error: true
          });
        });
        
        // Handle process completion
        pythonProcess.on('close', async (code) => {
          console.log(`Enhancement process exited with code ${code}`);
          
          // Update session status
          updateSessionStatus(sessionId, code === 0 ? 'complete' : 'failed');
          
          // Emit completion event
          io.to(sessionId).emit('process-complete', {
            type: 'enhance',
            success: code === 0,
            message: code === 0 ? 'Enhancement completed successfully' : 'Enhancement failed'
          });
          
          // Update Redis metadata if successful
          if (code === 0) {
            await scanMetadataSync.updateAfterEnhancement(scanId, provider, model);
            
            // Generate report using the web interface's report manager
            try {
              const reportManager = require('./utils/report-manager');
              
              // Generate HTML report from enhanced data
              console.log(`Generating HTML report for scan ${scanId} using web interface...`);
              const htmlContent = await reportManager.generateHtmlReport(scanId);
              
              // Save the report
              fs.writeFileSync(reportPath, htmlContent);
              
              console.log(`Generated HTML report at ${reportPath}`);
              
              // Notify the client
              io.to(sessionId).emit('scanner-output', {
                type: 'enhance',
                data: `\nGenerated HTML report at ${reportPath}\n`
              });
            } catch (reportError) {
              console.error(`Error generating report: ${reportError.message}`);
              io.to(sessionId).emit('scanner-output', {
                type: 'enhance',
                data: `\nError generating report: ${reportError.message}\n`,
                error: true
              });
            }
          }
        });
      } catch (error) {
        console.error(`Error enhancing scan results: ${error.message}`);
        
        // Notify the client of the error
        io.to(sessionId).emit('scanner-status', {
          type: 'enhance',
          success: false,
          output: `Error: ${error.message}`
        });
      }
    })();
  } catch (error) {
    console.error(`Error starting enhancement: ${error.message}`);
    res.status(500).json({
      success: false,
      message: `Error: ${error.message}`
    });
  }
});

// API endpoint to synchronize scan metadata from filesystem to Redis
app.post('/api/sync-metadata', async (req, res) => {
  try {
    // Perform the synchronization
    const result = await scanMetadataSync.syncFromFilesystemToRedis();
    
    // Return the result
    res.json({
      success: result.success,
      count: result.count,
      errors: result.errors
    });
  } catch (error) {
    console.error(`Error synchronizing metadata: ${error.message}`);
    res.status(500).json({
      success: false,
      message: `Error: ${error.message}`
    });
  }
});

// Dashboard route to display all scan results
app.get('/dashboard', async (req, res) => {
  try {
    // Get pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    
    // Get all scans with metadata
    const scans = await scanMetadataSync.getAllScansWithMetadata(limit, offset);
    
    // Get total count for pagination
    const allScanIds = await redis.getAllScanIds(1000, 0); // Get a large number to approximate total
    const totalScans = allScanIds.length;
    
    // Calculate pagination info
    const totalPages = Math.ceil(totalScans / limit);
    const hasMore = page < totalPages;
    
    // Sync metadata from filesystem to Redis to ensure we have the latest data
    console.log('Syncing metadata from filesystem to Redis for dashboard view');
    await scanMetadataSync.syncFromFilesystemToRedis();
    
    // Render the dashboard template
    res.render('dashboard', {
      title: 'Scan Results Dashboard',
      activeTab: 'dashboard',
      scans,
      pagination: {
        page,
        limit,
        totalScans,
        totalPages,
        hasMore
      }
    });
  } catch (error) {
    console.error(`Error loading dashboard: ${error.message}`);
    res.status(500).render('error', {
      title: 'Error',
      message: 'Failed to load dashboard',
      error: error.message
    });
  }
});

// Route to edit a report
app.get('/reports/:scanId/edit', redisSyncMiddleware.expressScanIdMiddleware, async (req, res) => {
  const { scanId } = req.params;
  
  try {
    console.log(`Looking for report for scan ID: ${scanId}`);
    
    // Get the scan metadata to check for the actual scan ID
    let scanMetadata = await redis.getScanMetadata(scanId);
    const actualScanId = scanMetadata?.actualScanId || scanId;
    console.log(`Using actual scan ID: ${actualScanId} (from filename: ${scanId})`);
    
    // Get all files in the reports directory
    const reportsDir = path.join(__dirname, '..', 'reports');
    const reportFiles = fs.readdirSync(reportsDir);
    
    // Look for any report file that contains the scanId
    let reportPath = null;
    
    // Try first with the actual scan ID if it's different
    if (actualScanId !== scanId) {
      const actualScanIdRegex = new RegExp(`.*${actualScanId}.*\.html$`);
      console.log(`Using regex pattern for actual scan ID: ${actualScanIdRegex}`);
      
      for (const file of reportFiles) {
        if (actualScanIdRegex.test(file)) {
          reportPath = path.join(reportsDir, file);
          console.log(`Found report matching actual scan ID regex: ${reportPath}`);
          break;
        }
      }
    }
    
    // If not found with actual scan ID, try with the filename
    if (!reportPath) {
      const scanIdRegex = new RegExp(`.*${scanId}.*\.html$`);
      console.log(`Using regex pattern for filename: ${scanIdRegex}`);
      
      for (const file of reportFiles) {
        if (scanIdRegex.test(file)) {
          reportPath = path.join(reportsDir, file);
          console.log(`Found report matching filename regex: ${reportPath}`);
          break;
        }
      }
    }
    
    // If no match with regex, try exact matches with common patterns as fallback
    if (!reportPath) {
      const possiblePatterns = [
        `report_${scanId}.html`,
        `${scanId}.html`,
        `enhanced_report_${scanId}.html`
      ];
      
      for (const pattern of possiblePatterns) {
        const testPath = path.join(reportsDir, pattern);
        console.log(`Checking for report with exact pattern: ${testPath}`);
        if (fs.existsSync(testPath)) {
          reportPath = testPath;
          console.log(`Found report with exact pattern: ${reportPath}`);
          break;
        }
      }
    }
    
    // Check if the hasReport flag in Redis is incorrect
    if (scanMetadata && scanMetadata.hasReport === 'false' && fs.existsSync(path.join(reportsDir, `report_${scanId}.html`))) {
      console.log(`Report exists but hasReport flag is false. Updating metadata for ${scanId}`);
      // Update the hasReport flag in Redis
      await redis.storeScanMetadata(actualScanId, { ...scanMetadata, hasReport: 'true' });
      reportPath = path.join(reportsDir, `report_${scanId}.html`);
    }
    
    // If no report file was found
    if (!reportPath) {
      console.log(`No report found for scanId: ${scanId}, checking for enhanced results files`);
      
      // Check the results directory for any enhanced results files that match the scanId
      const resultsDir = path.join(__dirname, '..', 'results');
      const resultFiles = fs.readdirSync(resultsDir);
      let enhancedResultsPath = null;
      
      // Try first with the actual scan ID if it's different
      if (actualScanId !== scanId) {
        const actualEnhancedRegex = new RegExp(`.*${actualScanId}.*(?:enhanced|llm).*\.json$`);
        console.log(`Using regex pattern for actual scan ID: ${actualEnhancedRegex} to find enhanced results`);
        
        for (const file of resultFiles) {
          if (actualEnhancedRegex.test(file)) {
            enhancedResultsPath = path.join(resultsDir, file);
            console.log(`Found enhanced results matching actual scan ID regex: ${enhancedResultsPath}`);
            break;
          }
        }
      }
      
      // If not found with actual scan ID, try with the filename
      if (!enhancedResultsPath) {
        const enhancedRegex = new RegExp(`.*${scanId}.*(?:enhanced|llm).*\.json$`);
        console.log(`Using regex pattern for filename: ${enhancedRegex} to find enhanced results`);
        
        for (const file of resultFiles) {
          if (enhancedRegex.test(file)) {
            enhancedResultsPath = path.join(resultsDir, file);
            console.log(`Found enhanced results matching filename regex: ${enhancedResultsPath}`);
            break;
          }
        }
      }
      
      // If no match with regex, try exact matches with common patterns as fallback
      if (!enhancedResultsPath) {
        // Look for different patterns of enhanced results files
        const enhancedPatterns = [
          `${scanId}_enhanced.json`,
          `enhanced_${scanId}.json`,
          `enhanced_${scanId}_description_enhanced.json`,
          `test_${scanId}.json`
        ];
        
        for (const pattern of enhancedPatterns) {
          const testPath = path.join(resultsDir, pattern);
          console.log(`Checking for enhanced results with exact pattern: ${testPath}`);
          if (fs.existsSync(testPath)) {
            enhancedResultsPath = testPath;
            console.log(`Found enhanced results with exact pattern: ${enhancedResultsPath}`);
            break;
          }
        }
      }
      
      // If still no match, try a more lenient approach - any JSON file with the scanId
      if (!enhancedResultsPath) {
        console.log(`No enhanced results found, trying any JSON file with scanId: ${scanId}`);
        for (const file of resultFiles) {
          if (file.includes(scanId) && file.endsWith('.json')) {
            enhancedResultsPath = path.join(resultsDir, file);
            console.log(`Found JSON file containing scanId: ${enhancedResultsPath}`);
            break;
          }
        }
      }
      
      if (enhancedResultsPath) {
        // Generate a report from the enhanced results
        console.log(`Generating report for ${scanId} from enhanced results: ${enhancedResultsPath}`);
        try {
          // Extract just the filename without path and extension
          const enhancedFileName = path.basename(enhancedResultsPath, '.json');
          const reportFileName = `report_${scanId}.html`;
          
          // Try to use our new utility script first
          const scriptPath = path.join(__dirname, '..', 'scripts', 'generate_missing_report.py');
          
          if (fs.existsSync(scriptPath)) {
            console.log(`Using generate_missing_report.py script to generate report for ${scanId}`);
            // Execute the script to generate the missing report
            const { execSync } = require('child_process');
            const result = execSync(`python3 ${scriptPath} ${scanId}`, {
              cwd: path.join(__dirname, '..'),
              encoding: 'utf8'
            });
            
            console.log(`Report generation result: ${result}`);
            reportPath = path.join(reportsDir, reportFileName);
          } else {
            // Fall back to the original method if script doesn't exist
            console.log(`Script not found, falling back to generateReportFromEnhancedResults`);
            await generateReportFromEnhancedResults(scanId, enhancedResultsPath, path.join(reportsDir, reportFileName));
            reportPath = path.join(reportsDir, reportFileName);
          }
          
          // Check if the report was generated successfully
          if (fs.existsSync(reportPath)) {
            console.log(`Successfully generated report for ${scanId} at ${reportPath}`);
          } else {
            return res.render('error', {
              title: 'Error',
              message: `Could not generate report for scan ID ${scanId}`
            });
          }
        } catch (genError) {
          console.error(`Error generating report: ${genError.message}`);
          return res.render('error', {
            title: 'Error',
            message: `Error generating report: ${genError.message}`
          });
        }
      } else {
        return res.render('error', {
          title: 'Error',
          message: `No enhanced results or report found for scan ID ${scanId}`
        });
      }
    }
    
    // Parse the JSON results file instead of the HTML report
    console.log(`Parsing JSON results for scan ID: ${scanId}`);
    let vulnerabilities = [];
    
    try {
      // First, check if we have complete vulnerability data in Redis
      console.log(`Checking for cached vulnerability data for scan ID: ${scanId}`);
      const cachedData = await redis.getCachedReportField(scanId, 'complete_vulnerability_data');
      
      if (cachedData) {
        try {
          // Parse the cached data
          vulnerabilities = JSON.parse(cachedData);
          console.log(`Loaded ${vulnerabilities.length} vulnerabilities from Redis cache`);
        } catch (parseError) {
          console.error(`Error parsing cached vulnerability data: ${parseError.message}`);
          // Continue with other methods if parsing fails
        }
      }
      
      // If no cached data, check for backup file
      if (vulnerabilities.length === 0) {
        const backupPath = path.join(__dirname, '..', 'results', `${scanId}_backup.json`);
        if (fs.existsSync(backupPath)) {
          try {
            const backupData = JSON.parse(fs.readFileSync(backupPath, 'utf8'));
            if (backupData.vulnerabilities && Array.isArray(backupData.vulnerabilities)) {
              vulnerabilities = backupData.vulnerabilities;
              console.log(`Loaded ${vulnerabilities.length} vulnerabilities from backup file`);
            }
          } catch (backupError) {
            console.error(`Error loading backup data: ${backupError.message}`);
            // Continue with other methods if backup loading fails
          }
        }
      }
      
      // If still no vulnerabilities, try parsing JSON results
      if (vulnerabilities.length === 0) {
        console.log(`Getting vulnerabilities from JSON results for scan ID: ${scanId}`);
        vulnerabilities = await parseResultsJson(scanId);
        console.log(`Extracted ${vulnerabilities.length} vulnerabilities from JSON results`);
      }
      
      // If still no vulnerabilities, fall back to HTML parsing as a last resort
      if (vulnerabilities.length === 0 && reportPath) {
        console.log(`No vulnerabilities found in previous methods, falling back to HTML parsing`);
        const reportContent = fs.readFileSync(reportPath, 'utf8');
        vulnerabilities = parseReportHtml(reportContent);
        console.log(`Extracted ${vulnerabilities.length} vulnerabilities from HTML report as fallback`);
      }
      
      // Log the first vulnerability for debugging
      if (vulnerabilities.length > 0) {
        console.log('First vulnerability:', JSON.stringify(vulnerabilities[0], null, 2));
      } else {
        console.log('No vulnerabilities found in the results');
      }
      
      // Clear existing vulnerability data in Redis
      console.log('Clearing existing vulnerability data in Redis...');
      const existingVulnIdsJson = await redis.getCachedReportField(scanId, 'vulnerability_ids');
      if (existingVulnIdsJson) {
        const existingVulnIds = JSON.parse(existingVulnIdsJson);
        for (const vulnId of existingVulnIds) {
          await redis.deleteCachedReportField(scanId, `${vulnId}_name`);
          await redis.deleteCachedReportField(scanId, `${vulnId}_url`); // Delete old URL field if it exists
          await redis.deleteCachedReportField(scanId, `${vulnId}_endpoint`); // Delete endpoint field
          await redis.deleteCachedReportField(scanId, `${vulnId}_description`);
          await redis.deleteCachedReportField(scanId, `${vulnId}_risk`);
          await redis.deleteCachedReportField(scanId, `${vulnId}_impact`);
          await redis.deleteCachedReportField(scanId, `${vulnId}_examples`);
          await redis.deleteCachedReportField(scanId, `${vulnId}_remediation`);
          await redis.deleteCachedReportField(scanId, `${vulnId}_evidence`);
        }
        await redis.deleteCachedReportField(scanId, 'vulnerability_ids');
      }
      
      // Cache the parsed vulnerabilities in Redis for future use
      console.log('Caching parsed vulnerabilities in Redis...');
      for (const vuln of vulnerabilities) {
        await redis.cacheReportField(scanId, `${vuln.id}_name`, vuln.name);
        await redis.cacheReportField(scanId, `${vuln.id}_endpoint`, vuln.url || ''); // Store as endpoint but keep property name as url for compatibility
        await redis.cacheReportField(scanId, `${vuln.id}_severity`, vuln.severity || '');
        await redis.cacheReportField(scanId, `${vuln.id}_description`, vuln.description);
        await redis.cacheReportField(scanId, `${vuln.id}_risk`, vuln.risk);
        await redis.cacheReportField(scanId, `${vuln.id}_impact`, vuln.impact);
        await redis.cacheReportField(scanId, `${vuln.id}_examples`, vuln.examples);
        await redis.cacheReportField(scanId, `${vuln.id}_remediation`, vuln.remediation);
        await redis.cacheReportField(scanId, `${vuln.id}_evidence`, vuln.evidence);
      }
      
      // Store the vulnerability IDs list for easy retrieval
      const vulnIds = vulnerabilities.map(v => v.id);
      await redis.cacheReportField(scanId, 'vulnerability_ids', JSON.stringify(vulnIds));
    } catch (redisError) {
      console.error(`Error getting vulnerability data from Redis: ${redisError.message}`);
      console.error(redisError.stack);
      
      // Fall back to parsing the HTML file
      const reportContent = fs.readFileSync(reportPath, 'utf8');
      vulnerabilities = parseReportHtml(reportContent);
    }
    
    // If we still have no vulnerabilities, create a placeholder
    if (vulnerabilities.length === 0) {
      console.log(`No vulnerabilities found for scan ID: ${scanId}, creating placeholder`);
      vulnerabilities.push({
        id: 'placeholder',
        name: 'Placeholder Vulnerability',
        description: 'No vulnerabilities were found in this scan. You can edit this placeholder to add information.',
        risk: '',
        impact: '',
        examples: '',
        remediation: '',
        evidence: ''
      });
    }
    
    // Get scan metadata for title and description (reuse existing scanMetadata if available)
    if (!scanMetadata) {
      scanMetadata = await redis.getScanMetadata(scanId);
    }
    const scanTitle = scanMetadata?.title || 'Untitled Scan';
    const scanDescription = scanMetadata?.description || '';
    
    // Add debugging information
    console.log(`Rendering edit-report with ${vulnerabilities.length} vulnerabilities`);
    console.log('First vulnerability:', vulnerabilities.length > 0 ? JSON.stringify(vulnerabilities[0], null, 2) : 'None');
    
    // Check for empty or malformed vulnerability data
    if (vulnerabilities.length === 0) {
      console.log('No vulnerabilities found, adding placeholder');
      vulnerabilities.push({
        id: 'placeholder',
        name: 'Placeholder Vulnerability',
        description: 'No vulnerabilities were found in this scan. You can edit this placeholder to add information.',
        risk: 'No risk assessment available.',
        impact: 'No impact analysis available.',
        examples: 'No examples available.',
        remediation: 'No remediation steps available.',
        evidence: 'No evidence available.'
      });
    }
    
    // Ensure all vulnerabilities have the required fields
    vulnerabilities = vulnerabilities.map(vuln => ({
      id: vuln.id || 'unknown',
      name: vuln.name || 'Unnamed Vulnerability',
      description: vuln.description || '',
      risk: vuln.risk || '',
      impact: vuln.impact || '',
      examples: vuln.examples || '',
      remediation: vuln.remediation || '',
      evidence: vuln.evidence || ''
    }));
    
    // Render the edit report page
    res.render('edit-report', {
      title: 'Edit Report',
      activeTab: 'results',
      scanId,
      scanTitle,
      scanDescription,
      vulnerabilities,
      debug: {
        vulnCount: vulnerabilities.length,
        hasMetadata: !!scanMetadata,
        reportPath: reportPath
      }
    });
  } catch (error) {
    console.error(`Error editing report: ${error.message}`);
    res.render('error', {
      title: 'Error',
      message: `Error editing report: ${error.message}`
    });
  }
});

// Route to save edited report
app.post('/reports/:scanId/save', async (req, res) => {
  const { scanId } = req.params;
  const { vulnerabilities } = req.body;
  
  try {
    console.log(`Saving report for scan ID: ${scanId} with ${vulnerabilities.length} vulnerabilities`);
    
    // Check if the report exists
    const reportPath = path.join(__dirname, '..', 'reports', `report_${scanId}.html`);
    
    if (!fs.existsSync(reportPath)) {
      console.log(`Report file not found at: ${reportPath}, attempting to generate it...`);
      
      // Try to generate the missing report using our utility script
      try {
        const scriptPath = path.join(__dirname, '..', 'scripts', 'generate_missing_report.py');
        
        if (!fs.existsSync(scriptPath)) {
          console.error(`Report generation script not found at: ${scriptPath}`);
          return res.status(404).json({
            success: false,
            error: `Report for scan ID ${scanId} not found and generation script is missing`
          });
        }
        
        // Execute the script to generate the missing report
        const { execSync } = require('child_process');
        const result = execSync(`python3 ${scriptPath} ${scanId}`, {
          cwd: path.join(__dirname, '..'),
          encoding: 'utf8'
        });
        
        console.log(`Report generation result: ${result}`);
        
        // Check if the report was generated successfully
        if (!fs.existsSync(reportPath)) {
          console.error(`Failed to generate report for scan ID: ${scanId}`);
          return res.status(404).json({
            success: false,
            error: `Failed to generate report for scan ID: ${scanId}`
          });
        }
        
        console.log(`Successfully generated missing report for scan ID: ${scanId}`);
      } catch (genError) {
        console.error(`Error generating report: ${genError.message}`);
        return res.status(500).json({
          success: false,
          error: `Error generating report: ${genError.message}`
        });
      }
    }
    
    // Define paths for both regular and enhanced results files
    const resultsPath = path.join(__dirname, '..', 'results', `${scanId}.json`);
    const enhancedResultsPath = path.join(__dirname, '..', 'results', `${scanId}_enhanced.json`);
    
    // Check which JSON file exists and use the enhanced version if available
    let jsonPath = fs.existsSync(enhancedResultsPath) ? enhancedResultsPath : resultsPath;
    let jsonExists = fs.existsSync(jsonPath);
    
    console.log(`JSON results file ${jsonExists ? 'exists' : 'does not exist'} at: ${jsonPath}`);
    
    // Read the original report content
    let reportContent = fs.readFileSync(reportPath, 'utf8');
    
    // If JSON file exists, read it to update with edited vulnerability data
    let jsonData = null;
    if (jsonExists) {
      try {
        const jsonContent = fs.readFileSync(jsonPath, 'utf8');
        jsonData = JSON.parse(jsonContent);
        console.log(`Successfully loaded JSON data from: ${jsonPath}`);
      } catch (jsonError) {
        console.error(`Error reading or parsing JSON file: ${jsonError.message}`);
        jsonExists = false;
      }
    }
    
    // Store the complete vulnerability data in Redis with a longer expiry (1 week)
    try {
      await redis.cacheReportField(scanId, 'complete_vulnerability_data', JSON.stringify(vulnerabilities), 604800);
      console.log(`Cached complete vulnerability data for scan ID: ${scanId}`);
    } catch (redisError) {
      console.error(`Error caching complete vulnerability data: ${redisError.message}`);
      // Continue with the save process even if Redis caching fails
    }
    
    // Update the report content and JSON data with edited vulnerability data
    for (const vuln of vulnerabilities) {
      console.log(`Processing vulnerability: ${vuln.id} - ${vuln.name}`);
      
      // Cache the edited fields in Redis with a longer expiry (1 week = 604800 seconds)
      await redis.cacheReportField(scanId, `${vuln.id}_endpoint`, vuln.url, 604800); // Store as endpoint but keep 'url' property name for compatibility
      await redis.cacheReportField(scanId, `${vuln.id}_severity`, vuln.severity, 604800);
      await redis.cacheReportField(scanId, `${vuln.id}_description`, vuln.description, 604800);
      await redis.cacheReportField(scanId, `${vuln.id}_risk`, vuln.risk, 604800);
      await redis.cacheReportField(scanId, `${vuln.id}_impact`, vuln.impact, 604800);
      await redis.cacheReportField(scanId, `${vuln.id}_examples`, vuln.examples, 604800);
      await redis.cacheReportField(scanId, `${vuln.id}_remediation`, vuln.remediation, 604800);
      
      // Update the JSON data if it exists
      if (jsonExists && jsonData && jsonData.scanners) {
        // Find the scanner containing this vulnerability
        for (const scanner of jsonData.scanners) {
          if (scanner.findings && Array.isArray(scanner.findings)) {
            // Find the finding that matches this vulnerability name
            for (const finding of scanner.findings) {
              if (finding.vulnerability && finding.vulnerability.toLowerCase().replace(/[^a-z0-9]/g, '_') === vuln.id) {
                console.log(`Updating finding in JSON data: ${finding.vulnerability}`);
                // Update the finding with edited data
                finding.severity = vuln.severity;
                finding.endpoint = vuln.url;
                finding.details = vuln.description;
                // Store additional fields in a metadata object if they don't exist in the original structure
                finding.metadata = finding.metadata || {};
                finding.metadata.risk = vuln.risk;
                finding.metadata.impact = vuln.impact;
                finding.metadata.examples = vuln.examples;
                finding.metadata.remediation = vuln.remediation;
              }
            }
          }
        }
      }
      
      // Try to update the report using the new vulnerability div format first
      const vulnNameEscaped = vuln.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      
      // First try to match the new format with vulnerability divs
      const newFormatRegex = new RegExp(`<div class="vulnerability[^"]*">\\s*<div class="vuln-header">\\s*<h3>[^<]*${vulnNameEscaped}</h3>[\\s\\S]*?(?=<div class="vulnerability|$)`, 'i');
      
      let updated = false;
      
      reportContent = reportContent.replace(newFormatRegex, (match) => {
        updated = true;
        console.log(`Updating vulnerability in new format: ${vuln.name}`);
        
        // Update severity class and text
        let result = match.replace(/<span class="severity[^"]*">([^<]+)<\/span>/, 
          `<span class="severity ${vuln.severity.toLowerCase()}">${vuln.severity}</span>`);
        
        // Update Endpoint (previously URL)
        // First try to update Endpoint if it exists
        let endpointUpdated = false;
        result = result.replace(
          /(<div class="section">\s*<div class="section-title">Endpoint:<\/div>\s*<div>)[^<]*(<\/div>)/,
          (match, p1, p2) => {
            endpointUpdated = true;
            return `${p1}${vuln.url}${p2}`;
          }
        );
        
        // If Endpoint wasn't found, check for URL and update it
        if (!endpointUpdated) {
          // Try to replace URL with Endpoint
          result = result.replace(
            /(<div class="section">\s*<div class="section-title">)URL:(<\/div>\s*<div>)[^<]*(<\/div>)/,
            `$1Endpoint:$2${vuln.url}$3`
          );
        }
        
        // Update description
        result = result.replace(
          /(<div class="section">\s*<div class="section-title">Description:<\/div>\s*<div>)[\s\S]*?(<\/div>\s*<\/div>)/,
          `$1${vuln.description}$2`
        );
        
        // Update risk
        result = result.replace(
          /(<div class="section">\s*<div class="section-title">Risk:<\/div>\s*<div>)[\s\S]*?(<\/div>\s*<\/div>)/,
          `$1${vuln.risk}$2`
        );
        
        // Update impact
        result = result.replace(
          /(<div class="section">\s*<div class="section-title">Impact:<\/div>\s*<div>)[\s\S]*?(<\/div>\s*<\/div>)/,
          `$1${vuln.impact}$2`
        );
        
        // Update examples
        result = result.replace(
          /(<div class="section">\s*<div class="section-title">Examples:<\/div>\s*<div>)[\s\S]*?(<\/div>\s*<\/div>)/,
          `$1${vuln.examples}$2`
        );
        
        // Update remediation
        result = result.replace(
          /(<div class="section">\s*<div class="section-title">Remediation:<\/div>\s*<div>)[\s\S]*?(<\/div>\s*<\/div>)/,
          `$1${vuln.remediation}$2`
        );
        
        return result;
      });
      
      // If the new format wasn't found, try the old h2 format
      if (!updated) {
        console.log(`Falling back to old format for: ${vuln.name}`);
        const vulnSectionRegex = new RegExp(`<h2>${vulnNameEscaped}</h2>([\\s\\S]*?)(?=<h2>|$)`, 'g');
        
        reportContent = reportContent.replace(vulnSectionRegex, (match, content) => {
          // Replace description
          content = content.replace(
            /(<h3>Description<\/h3>)[\s\S]*?(?=<h3>|$)/,
            `$1\n${vuln.description}\n`
          );
          
          // Replace risk assessment
          content = content.replace(
            /(<h3>Risk Assessment<\/h3>)[\s\S]*?(?=<h3>|$)/,
            `$1\n${vuln.risk}\n`
          );
          
          // Replace impact analysis
          content = content.replace(
            /(<h3>Impact Analysis<\/h3>)[\s\S]*?(?=<h3>|$)/,
            `$1\n${vuln.impact}\n`
          );
          
          // Replace real-world examples
          content = content.replace(
            /(<h3>Real-World Examples<\/h3>)[\s\S]*?(?=<h3>|$)/,
            `$1\n${vuln.examples}\n`
          );
          
          // Replace remediation
          content = content.replace(
            /(<h3>Remediation<\/h3>)[\s\S]*?(?=<h3>|$)/,
            `$1\n${vuln.remediation}\n`
          );
          
          // Replace URL with Endpoint or add Endpoint if not present
          const hasEndpoint = /<h3>Endpoint<\/h3>/.test(content);
          const hasUrl = /<h3>URL<\/h3>/.test(content);
          
          if (hasEndpoint) {
            // Update existing Endpoint
            content = content.replace(
              /(<h3>Endpoint<\/h3>)[\s\S]*?(?=<h3>|$)/,
              `$1\n${vuln.url}\n`
            );
          } else if (hasUrl) {
            // Replace URL with Endpoint
            content = content.replace(
              /(<h3>)URL(<\/h3>)[\s\S]*?(?=<h3>|$)/,
              `$1Endpoint$2\n${vuln.url}\n`
            );
          } else {
            // Add Endpoint section if neither exists
            content = `<h3>Endpoint</h3>\n${vuln.url}\n${content}`;
          }
          
          return `<h2>${vuln.name}</h2>${content}`;
        });
      }
    }
    
    // Write the updated report back to the file
    fs.writeFileSync(reportPath, reportContent, 'utf8');
    console.log(`Updated HTML report saved to: ${reportPath}`);
    
    // If we have JSON data, write it back to the file
    if (jsonExists && jsonData) {
      try {
        fs.writeFileSync(jsonPath, JSON.stringify(jsonData, null, 2), 'utf8');
        console.log(`Successfully updated JSON data at: ${jsonPath}`);
      } catch (jsonWriteError) {
        console.error(`Error writing JSON file: ${jsonWriteError.message}`);
        // Continue even if JSON write fails - we at least updated the HTML report
      }
    }
    
    // Create a backup of the vulnerability data
    try {
      const backupPath = path.join(__dirname, '..', 'results', `${scanId}_backup.json`);
      fs.writeFileSync(backupPath, JSON.stringify({
        scanId,
        timestamp: Date.now(),
        vulnerabilities
      }, null, 2), 'utf8');
      console.log(`Created backup of vulnerability data at: ${backupPath}`);
    } catch (backupError) {
      console.error(`Error creating backup: ${backupError.message}`);
      // Continue even if backup fails
    }
    
    // Update scan metadata to indicate the report has been edited
    try {
      const scanMetadata = await redis.getScanMetadata(scanId) || {};
      await redis.storeScanMetadata(scanId, {
        ...scanMetadata,
        lastEdited: Date.now().toString(),
        hasReport: 'true'
      });
    } catch (metadataError) {
      console.error(`Error updating scan metadata: ${metadataError.message}`);
      // Continue even if metadata update fails
    }
    
    res.json({
      success: true,
      message: 'Report and JSON data saved successfully'
    });
  } catch (error) {
    console.error(`Error saving report: ${error.message}`);
    res.status(500).json({
      success: false,
      error: `Error saving report: ${error.message}`
    });
  }
});

// API endpoint for enhancing a specific section of a vulnerability
app.post('/api/reports/:scanId/enhance-section', redisSyncMiddleware.expressScanIdMiddleware, async (req, res) => {
  const { scanId } = req.params;
  const { 
    vulnId, 
    section, 
    provider, 
    model, 
    enhanceOption, 
    instructions, 
    currentContent, 
    vulnDetails,
    sessionId 
  } = req.body;
  
  // Validate required fields
  if (!vulnId || !section || !provider || !model || !vulnDetails || !sessionId) {
    return res.status(400).json({
      success: false,
      message: 'Missing required fields'
    });
  }
  
  // Send initial response to client
  res.json({
    success: true,
    message: 'Section enhancement process started',
    sessionId,
    scanId,
    vulnId,
    section
  });
  
  // Process the enhancement asynchronously
  (async () => {
    try {
      // Create a temporary file with the vulnerability details and prompt
      const tempDir = path.join(__dirname, '..', 'temp');
      if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
      }
      
      // Create a unique temp file name
      const tempFileName = `section_enhance_${scanId}_${vulnId}_${section}_${Date.now()}.json`;
      const tempFilePath = path.join(tempDir, tempFileName);
      
      // Get the prompt template from the prompt manager
      let prompt = '';
      const { spawn } = require('child_process');
      const pythonPath = process.env.PYTHON_PATH || 'python3';
      const promptManagerPath = path.join(__dirname, '..', 'utils', 'prompt_manager.py');
      
      // Function to get prompt template
      const getPromptTemplate = (promptKey) => {
        return new Promise((resolve, reject) => {
          const process = spawn(pythonPath, [promptManagerPath, 'get', promptKey]);
          
          let stdout = '';
          let stderr = '';
          
          process.stdout.on('data', (data) => {
            stdout += data.toString();
          });
          
          process.stderr.on('data', (data) => {
            stderr += data.toString();
          });
          
          process.on('close', (code) => {
            if (code === 0) {
              resolve(stdout.trim());
            } else {
              console.error(`Error getting prompt template: ${stderr}`);
              reject(new Error(`Process exited with code ${code}: ${stderr}`));
            }
          });
        });
      };
      
      try {
        // Get the appropriate template based on section
        const promptKey = `section_templates.${section}`;
        const template = await getPromptTemplate(promptKey);
        
        if (template) {
          // Replace variables in the template
          prompt = template
            .replace(/{vulnerability_name}/g, vulnDetails.name)
            .replace(/{vulnerability}/g, vulnDetails.name)
            .replace(/{severity}/g, vulnDetails.severity || 'Unknown')
            .replace(/{endpoint}/g, vulnDetails.url || 'Not specified')
            .replace(/{evidence}/g, vulnDetails.evidence || 'Not available');
        } else {
          // Fallback to default prompts if template not found
          console.log(`No template found for ${promptKey}, using default prompt`);
          switch (section) {
            case 'description':
              prompt = `Generate a detailed description for the vulnerability: ${vulnDetails.name}. `;
              prompt += `This should explain what the vulnerability is, how it works, and why it's a security concern. `;
              break;
            case 'risk':
              prompt = `Generate a comprehensive risk assessment for the vulnerability: ${vulnDetails.name}. `;
              prompt += `Explain the potential risks to the organization if this vulnerability is exploited. `;
              break;
            case 'impact':
              prompt = `Generate an impact analysis for the vulnerability: ${vulnDetails.name}. `;
              prompt += `Describe the potential impact on the organization, users, and data if this vulnerability is exploited. `;
              break;
            case 'examples':
              prompt = `Provide real-world examples of how the vulnerability: ${vulnDetails.name} has been exploited in the past. `;
              prompt += `Include notable security incidents, breaches, or attacks that utilized this type of vulnerability. `;
              break;
            case 'remediation':
              prompt = `Provide detailed remediation steps for the vulnerability: ${vulnDetails.name}. `;
              prompt += `Include specific code examples, configuration changes, or best practices to fix this issue. `;
              break;
            default:
              prompt = `Generate enhanced content for the ${section} section of the vulnerability: ${vulnDetails.name}. `;
          }
        }
      } catch (error) {
        console.error(`Error loading prompt template: ${error.message}`);
        // Fallback to default prompts
        switch (section) {
          case 'description':
            prompt = `Generate a detailed description for the vulnerability: ${vulnDetails.name}. `;
            prompt += `This should explain what the vulnerability is, how it works, and why it's a security concern. `;
            break;
          case 'risk':
            prompt = `Generate a comprehensive risk assessment for the vulnerability: ${vulnDetails.name}. `;
            prompt += `Explain the potential risks to the organization if this vulnerability is exploited. `;
            break;
          case 'impact':
            prompt = `Generate an impact analysis for the vulnerability: ${vulnDetails.name}. `;
            prompt += `Describe the potential impact on the organization, users, and data if this vulnerability is exploited. `;
            break;
          case 'examples':
            prompt = `Provide real-world examples of how the vulnerability: ${vulnDetails.name} has been exploited in the past. `;
            prompt += `Include notable security incidents, breaches, or attacks that utilized this type of vulnerability. `;
            break;
          case 'remediation':
            prompt = `Provide detailed remediation steps for the vulnerability: ${vulnDetails.name}. `;
            prompt += `Include specific code examples, configuration changes, or best practices to fix this issue. `;
            break;
          default:
            prompt = `Generate enhanced content for the ${section} section of the vulnerability: ${vulnDetails.name}. `;
        }
      }
      
      // Add severity context
      prompt += `The severity of this vulnerability is ${vulnDetails.severity}. `;
      
      // Add URL context if available
      if (vulnDetails.url) {
        prompt += `The affected endpoint is: ${vulnDetails.url}. `;
      }
      
      // Add evidence context if available
      if (vulnDetails.evidence) {
        prompt += `Here is the evidence of the vulnerability: ${vulnDetails.evidence}. `;
      }
      
      // Add existing content if improving
      if (enhanceOption === 'improve' && currentContent) {
        prompt += `Improve the following existing content, maintaining its structure but enhancing the details and clarity: ${currentContent}. `;
      }
      
      // Add additional instructions if provided
      if (instructions) {
        prompt += `Additional instructions: ${instructions}`;
      }
      
      // Create the temp file content
      const tempFileContent = {
        prompt,
        vulnDetails,
        section,
        currentContent: enhanceOption === 'improve' ? currentContent : ''
      };
      
      // Write to temp file
      fs.writeFileSync(tempFilePath, JSON.stringify(tempFileContent, null, 2));
      
      // Build the command for the Python script
      const pythonScript = path.join(__dirname, '..', 'scripts', 'enhance_section.py');
      
      // Create the Python script if it doesn't exist
      if (!fs.existsSync(pythonScript)) {
        const scriptDir = path.join(__dirname, '..', 'scripts');
        if (!fs.existsSync(scriptDir)) {
          fs.mkdirSync(scriptDir, { recursive: true });
        }
        
        // Create a simple Python script for section enhancement
        const pythonScriptContent = `#!/usr/bin/env python3
"""
Enhance a specific section of a vulnerability report using an LLM.
"""

import argparse
import json
import os
import sys
import time

def get_llm_response(prompt, provider, model, api_key=None):
    """Get a response from the LLM based on the provider."""
    if provider == 'ollama':
        try:
            import ollama
            response = ollama.chat(model=model, messages=[{'role': 'user', 'content': prompt}])
            return response['message']['content']
        except Exception as e:
            print(f"Error with Ollama: {str(e)}", file=sys.stderr)
            return None
    elif provider == 'openai':
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"Error with OpenAI: {str(e)}", file=sys.stderr)
            return None
    else:
        print(f"Unsupported provider: {provider}", file=sys.stderr)
        return None

def main():
    parser = argparse.ArgumentParser(description='Enhance a section of a vulnerability report')
    parser.add_argument('--input', required=True, help='Input JSON file with vulnerability details')
    parser.add_argument('--output', required=True, help='Output file for enhanced content')
    parser.add_argument('--provider', required=True, help='LLM provider (ollama or openai)')
    parser.add_argument('--model', required=True, help='LLM model name')
    parser.add_argument('--api-key', help='API key for the LLM provider')
    
    args = parser.parse_args()
    
    try:
        # Load the input file
        print(f"Loading input file: {args.input}")
        with open(args.input, 'r') as f:
            data = json.load(f)
        
        prompt = data.get('prompt', '')
        if not prompt:
            print("Error: No prompt found in input file", file=sys.stderr)
            sys.exit(1)
        
        print(f"Enhancing section with {args.provider} {args.model}")
        print(f"Progress: 1/3 (33.3%)")
        
        # Get the LLM response
        enhanced_content = get_llm_response(prompt, args.provider, args.model, args.api_key)
        
        if not enhanced_content:
            print("Error: Failed to get response from LLM", file=sys.stderr)
            sys.exit(1)
        
        print(f"Progress: 2/3 (66.7%)")
        time.sleep(1)  # Simulate processing time
        
        # Write the output
        with open(args.output, 'w') as f:
            f.write(enhanced_content)
        
        print(f"Progress: 3/3 (100.0%)")
        print(f"Enhanced content written to: {args.output}")
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
`;
        
        fs.writeFileSync(pythonScript, pythonScriptContent);
        fs.chmodSync(pythonScript, '755'); // Make executable
      }
      
      // Output file path
      const outputFilePath = path.join(tempDir, `section_output_${scanId}_${vulnId}_${section}_${Date.now()}.html`);
      
      // Build the command arguments
      const args = [
        pythonScript,
        '--input', tempFilePath,
        '--output', outputFilePath,
        '--provider', provider,
        '--model', model,
        '--section', section,
        '--debug'
      ];
      
      // If using OpenAI, pass the API key from environment variable
      if (provider === 'openai') {
        const apiKey = process.env.LLM_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
        if (apiKey) {
          args.push('--api-key', apiKey);
        }
      }
      
      // Start the process
      console.log(`Running command: python3 ${args.join(' ')}`);
      
      // Use the root directory as cwd
      const rootDir = path.join(__dirname, '..');
      console.log(`Using working directory: ${rootDir}`);
      
      const pythonProcess = spawn('python3', args, { 
        cwd: rootDir,
        env: { ...process.env }
      });
      
      // Track the process if session ID is provided
      const { setSession, updateSessionStatus } = require('./utils/session-store');
      setSession(sessionId, {
        process: pythonProcess,
        type: 'enhance-section',
        startTime: Date.now(),
        paused: false,
        output: ''
      });
      
      let output = '';
      
      pythonProcess.stdout.on('data', (data) => {
        const chunk = data.toString();
        output += chunk;
        console.log(chunk);
        
        // Check for progress information in the output
        // More flexible regex pattern to match different progress formats
        const progressMatch = chunk.match(/Progress:?\s*(\d+)\s*\/\s*(\d+)\s*\(?\s*(\d+(?:\.\d+)?)\s*%\)?/i);
        if (progressMatch) {
          const current = parseInt(progressMatch[1]);
          const total = parseInt(progressMatch[2]);
          const percentage = parseFloat(progressMatch[3]);
          
          // Emit progress update
          io.to(sessionId).emit('enhancement-progress', {
            current,
            total,
            percentage
          });
        }
        
        // Emit to specific session
        io.to(sessionId).emit('scanner-output', {
          type: 'enhance-section',
          data: chunk
        });
      });
      
      pythonProcess.stderr.on('data', (data) => {
        const chunk = data.toString();
        output += chunk;
        console.error(chunk);
        
        // Emit to specific session
        io.to(sessionId).emit('scanner-output', {
          type: 'enhance-section',
          data: chunk,
          error: true
        });
      });
      
      pythonProcess.on('close', async (code) => {
        console.log(`Section enhancement process exited with code ${code}`);
        
        // Check if the output file exists
        if (code === 0 && fs.existsSync(outputFilePath)) {
          try {
            // Read the enhanced content
            const enhancedContent = fs.readFileSync(outputFilePath, 'utf8');
            
            // Update scan metadata to ensure enhanced version replaces original in UI
            const updateMetadataScript = path.join(__dirname, '..', 'scripts', 'update_scan_metadata.py');
            const metadataOutputFile = path.join(tempDir, `metadata_update_${scanId}_${vulnId}_${section}_${Date.now()}.log`);
            
            try {
              // Save enhanced content to a temporary file for metadata update
              const enhancedContentFile = path.join(tempDir, `enhanced_content_${scanId}_${vulnId}_${section}_${Date.now()}.html`);
              fs.writeFileSync(enhancedContentFile, enhancedContent);
              
              // Run the metadata update script
              const updateProcess = spawn('python3', [
                updateMetadataScript,
                '--scan-id', scanId,
                '--section', section,
                '--content-file', enhancedContentFile
              ]);
              
              let updateOutput = '';
              updateProcess.stdout.on('data', (data) => {
                updateOutput += data.toString();
              });
              
              updateProcess.stderr.on('data', (data) => {
                updateOutput += data.toString();
                console.error(`Metadata update error: ${data.toString()}`);
              });
              
              updateProcess.on('close', (updateCode) => {
                console.log(`Metadata update process exited with code ${updateCode}`);
                
                // Emit completion event with the enhanced content
                io.to(sessionId).emit('section-enhancement-complete', {
                  success: true,
                  content: enhancedContent,
                  section,
                  vulnId,
                  timestamp: new Date().toISOString(),
                  metadataUpdated: updateCode === 0,
                  metadataUpdateOutput: updateOutput
                });
                
                // Clean up temporary files
                try {
                  fs.unlinkSync(tempFilePath);
                  fs.unlinkSync(outputFilePath);
                  fs.unlinkSync(enhancedContentFile);
                } catch (cleanupError) {
                  console.warn(`Warning: Could not clean up temporary files: ${cleanupError.message}`);
                }
              });
            } catch (metadataError) {
              console.error(`Error updating metadata: ${metadataError.message}`);
              
              // Still emit completion event with the enhanced content
              io.to(sessionId).emit('section-enhancement-complete', {
                success: true,
                content: enhancedContent,
                section,
                vulnId,
                timestamp: new Date().toISOString(),
                metadataUpdated: false,
                metadataError: metadataError.message
              });
              
              // Clean up temporary files
              try {
                fs.unlinkSync(tempFilePath);
                fs.unlinkSync(outputFilePath);
              } catch (cleanupError) {
                console.warn(`Warning: Could not clean up temporary files: ${cleanupError.message}`);
              }
            }
            
          } catch (readError) {
            console.error(`Error reading enhanced content: ${readError.message}`);
            io.to(sessionId).emit('section-enhancement-complete', {
              success: false,
              error: `Error reading enhanced content: ${readError.message}`,
              section,
              vulnId,
              timestamp: new Date().toISOString()
            });
          }
        } else {
          // Process failed or output file doesn't exist
          const errorMessage = code === 0 
            ? `Output file not found: ${outputFilePath}` 
            : `Enhancement process failed with exit code ${code}`;
          
          console.error(errorMessage);
          io.to(sessionId).emit('section-enhancement-complete', {
            success: false,
            error: errorMessage,
            section,
            vulnId,
            timestamp: new Date().toISOString(),
            output: output.split('\n').slice(-20).join('\n') // Last 20 lines of output for debugging
          });
        }
      });
      
    } catch (error) {
      console.error(`Error processing section enhancement: ${error.message}`);
      io.to(sessionId).emit('section-enhancement-complete', {
        success: false,
        error: `Error: ${error.message}`,
        section,
        vulnId
      });
    }
  })();
});

// Start the server
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Open your browser at http://localhost:${PORT} to use the API Security Scanner interface`);
});
