const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const { promisify } = require('util');
const readFileAsync = promisify(fs.readFile);
const writeFileAsync = promisify(fs.writeFile);
const redis = require('redis');

// Redis client setup
let redisClient;

// Initialize Redis client
function initRedisClient() {
    if (!redisClient || !redisClient.isOpen) {
        redisClient = redis.createClient({
            url: `redis://${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || 6379}/${process.env.REDIS_DB || 1}`
        });

        redisClient.on('error', (err) => {
            console.error('Redis client error:', err);
        });

        redisClient.on('connect', () => {
            console.log('Redis connection established');
        });

        redisClient.on('ready', () => {
            console.log('Redis client is ready');
        });

        // Connect to Redis
        redisClient.connect().catch(err => {
            console.error('Failed to connect to Redis:', err);
        });
    }
    return redisClient;
}

// Configuration
const PROMPTS_CONFIG_FILE = path.join(__dirname, '../../configs/llm_prompts.json');
const BACKUP_DIR = path.join(__dirname, '../../configs/backups');
const SETTINGS_FILE = path.join(__dirname, '../../configs/llm_settings.json');

// Ensure backup directory exists
if (!fs.existsSync(BACKUP_DIR)) {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

// Helper function to get backup files
async function getBackupFiles() {
    try {
        if (!fs.existsSync(BACKUP_DIR)) {
            return [];
        }
        
        const files = fs.readdirSync(BACKUP_DIR)
            .filter(file => file.startsWith('llm_prompts') && file.endsWith('.backup'))
            .map(file => {
                const stats = fs.statSync(path.join(BACKUP_DIR, file));
                return {
                    filename: file,
                    date: new Date(stats.mtime).toLocaleString(),
                    size: stats.size
                };
            })
            .sort((a, b) => new Date(b.date) - new Date(a.date));
        
        console.log(`Found ${files.length} backup files`);
        return files;
    } catch (error) {
        console.error('Error getting backup files:', error);
        return [];
    }
}

// Helper function to load settings
async function loadSettings() {
    try {
        if (fs.existsSync(SETTINGS_FILE)) {
            const data = await readFileAsync(SETTINGS_FILE, 'utf8');
            return JSON.parse(data);
        }
        return {
            defaultProvider: 'ollama',
            defaultModel: 'llama3.3'
        };
    } catch (error) {
        console.error('Error loading settings:', error);
        return {
            defaultProvider: 'ollama',
            defaultModel: 'llama3.3'
        };
    }
}

// Main page
router.get('/', async (req, res) => {
    try {
        // Count the total number of prompts in Redis
        const client = initRedisClient();
        const allPromptKeys = await client.keys('llm:prompt:*');
        const totalTemplates = allPromptKeys.length;
        console.log(`Total prompts in Redis: ${totalTemplates}`);
        
        // Get backups
        const backups = await getBackupFiles();
        
        // Get settings
        const settings = await loadSettings();
        
        console.log('Rendering admin_prompts template with data');
        res.render('admin_prompts', {
            title: 'LLM Prompt Management',
            activeTab: 'admin-prompts',
            backups,
            settings,
            totalTemplates: totalTemplates,
            message: req.query.message || '',
            messageType: req.query.messageType || 'info'
        });
    } catch (error) {
        console.error('Error loading admin prompts page:', error);
        res.render('error', {
            message: 'Error loading prompts admin page',
            error: {
                status: 500,
                stack: process.env.NODE_ENV === 'development' ? error.stack : ''
            }
        });
    }
});

// Create a backup
router.post('/backup/create', async (req, res) => {
    try {
        const client = initRedisClient();
        
        // Get all prompts from Redis
        const keys = await client.keys('llm:prompt:*');
        
        if (!keys || keys.length === 0) {
            return res.json({ success: false, error: 'No prompts found to backup' });
        }
        
        // Create an object to store all prompts
        const prompts = {};
        
        // Fetch each prompt
        for (const key of keys) {
            const promptJson = await client.get(key);
            if (promptJson) {
                try {
                    // Handle double-quoted JSON strings
                    let prompt;
                    if (promptJson.startsWith('"') && promptJson.endsWith('"')) {
                        // This is a double-quoted string, parse it as JSON
                        prompt = JSON.parse(promptJson);
                    } else {
                        // This is already a JSON object
                        prompt = JSON.parse(promptJson);
                    }
                    
                    const promptId = key.replace('llm:prompt:', '');
                    prompts[promptId] = prompt;
                } catch (error) {
                    console.error(`Error parsing prompt ${key}:`, error);
                    // Store the raw value if parsing fails
                    prompts[key.replace('llm:prompt:', '')] = promptJson;
                }
            }
        }
        
        // Create a timestamp for the backup filename
        const timestamp = new Date().toISOString().replace(/[:.]/g, '').substring(0, 14);
        const backupFile = path.join(BACKUP_DIR, `llm_prompts.json.${timestamp}.backup`);
        
        // Save the prompts to the backup file
        await writeFileAsync(backupFile, JSON.stringify(prompts, null, 2));
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error creating backup:', error);
        res.json({ success: false, error: error.message });
    }
});

// Restore from backup
router.post('/backup/restore', express.json(), async (req, res) => {
    try {
        const { filename } = req.body;
        
        if (!filename) {
            return res.json({ success: false, error: 'Missing filename' });
        }
        
        const backupFile = path.join(BACKUP_DIR, filename);
        
        if (!fs.existsSync(backupFile)) {
            return res.json({ success: false, error: 'Backup file not found' });
        }
        
        // Read the backup file
        const data = await readFileAsync(backupFile, 'utf8');
        const prompts = JSON.parse(data);
        
        const client = initRedisClient();
        
        // Save the prompts to Redis
        for (const [id, prompt] of Object.entries(prompts)) {
            if (typeof prompt === 'object') {
                await client.set(`llm:prompt:${id}`, JSON.stringify(prompt));
            } else {
                // If it's not an object, store it as is
                await client.set(`llm:prompt:${id}`, JSON.stringify(prompt));
            }
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error restoring backup:', error);
        res.json({ success: false, error: error.message });
    }
});

// Delete a backup
router.post('/backup/delete', express.json(), async (req, res) => {
    try {
        const { filename } = req.body;
        
        if (!filename) {
            return res.json({ success: false, error: 'Missing filename' });
        }
        
        const backupFile = path.join(BACKUP_DIR, filename);
        
        if (!fs.existsSync(backupFile)) {
            return res.json({ success: false, error: 'Backup file not found' });
        }
        
        // Delete the backup file
        fs.unlinkSync(backupFile);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting backup:', error);
        res.json({ success: false, error: error.message });
    }
});

// Update settings
router.post('/settings/update', express.json(), async (req, res) => {
    try {
        const { defaultProvider, defaultModel } = req.body;
        
        if (!defaultProvider || !defaultModel) {
            return res.json({ success: false, error: 'Missing required fields' });
        }
        
        // Save the settings
        await writeFileAsync(SETTINGS_FILE, JSON.stringify({
            defaultProvider,
            defaultModel
        }, null, 2));
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating settings:', error);
        res.json({ success: false, error: error.message });
    }
});

// List prompts by type (scan, report, vulnerability)
router.get('/list/:type', async (req, res) => {
    try {
        const { type } = req.params;
        const validTypes = ['scan', 'report', 'vulnerability'];
        
        if (!validTypes.includes(type)) {
            return res.json({ success: false, error: 'Invalid prompt type' });
        }
        
        const client = initRedisClient();
        
        // Get all prompts from Redis
        const keys = await client.keys('llm:prompt:*');
        console.log(`Found ${keys.length} total prompt keys in Redis`);
        
        if (!keys || keys.length === 0) {
            return res.json({ success: true, prompts: [] });
        }
        
        // Instead of filtering by prefix, categorize prompts after loading them
        const prompts = [];
        
        // Fetch each prompt
        for (const key of keys) {
            try {
                const promptJson = await client.get(key);
                if (!promptJson) continue;
                
                // Handle double-quoted JSON strings
                let prompt;
                try {
                    if (promptJson.startsWith('"') && promptJson.endsWith('"')) {
                        // This is a double-quoted string, parse it as JSON
                        prompt = JSON.parse(promptJson);
                    } else {
                        // This is already a JSON object
                        prompt = JSON.parse(promptJson);
                    }
                } catch (parseError) {
                    console.error(`Error parsing prompt JSON for key ${key}:`, parseError);
                    continue;
                }
                
                // Extract the prompt ID from the key
                const promptId = key.replace('llm:prompt:', '');
                
                // Determine the prompt type based on content analysis
                let promptType = 'unknown';
                const templateContent = prompt.template || '';
                const promptName = prompt.name || '';
                const promptDesc = prompt.description || '';
                
                // Check if this is a section template
                if (promptId.startsWith('section_templates.')) {
                    // All section templates are considered 'report' type
                    promptType = 'report';
                } 
                // Check for vulnerability-related prompts
                else if (
                    promptId.includes('vulnerability') || 
                    promptName.toLowerCase().includes('vulnerability') ||
                    promptDesc.toLowerCase().includes('vulnerability') ||
                    templateContent.includes('vulnerability')
                ) {
                    promptType = 'vulnerability';
                }
                // Check for report-related prompts
                else if (
                    promptId.includes('report') || 
                    promptName.toLowerCase().includes('report') ||
                    promptDesc.toLowerCase().includes('report') ||
                    templateContent.includes('report')
                ) {
                    promptType = 'report';
                }
                // Check for scan-related prompts
                else if (
                    promptId.includes('scan') || 
                    promptName.toLowerCase().includes('scan') ||
                    promptDesc.toLowerCase().includes('scan') ||
                    templateContent.includes('scan')
                ) {
                    promptType = 'scan';
                }
                // Default categorization for remaining prompts
                else {
                    // For the configs/llm_prompts.json file, categorize as follows:
                    if (promptId === 'description_template') {
                        promptType = 'vulnerability';
                    } else if (promptId === 'remediation_template') {
                        promptType = 'vulnerability';
                    } else {
                        // If we can't determine the type, show it in all categories
                        // This ensures users can see all prompts
                        promptType = type; // Just match whatever type was requested
                    }
                }
                
                // Only include prompts of the requested type
                if (promptType === type) {
                    prompts.push({
                        id: promptId,
                        name: prompt.name || promptId,
                        description: prompt.description || '',
                        category: prompt.category || 'General',
                        // Don't include the full template in the list to reduce payload size
                    });
                }
            } catch (error) {
                console.error(`Error processing prompt ${key}:`, error);
            }
        }
        
        console.log(`Filtered to ${prompts.length} prompts of type '${type}'`);
        res.json({ success: true, prompts });
    } catch (error) {
        console.error('Error listing prompts:', error);
        res.json({ success: false, error: error.message });
    }
});

// View a specific prompt template
router.get('/view/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        if (!id) {
            return res.json({ success: false, error: 'Missing prompt ID' });
        }
        
        console.log(`Attempting to view prompt with ID: ${id}`);
        const client = initRedisClient();
        
        // Get the prompt from Redis
        const redisKey = `llm:prompt:${id}`;
        console.log(`Looking up Redis key: ${redisKey}`);
        const promptJson = await client.get(redisKey);
        
        if (!promptJson) {
            console.log(`Prompt not found for key: ${redisKey}`);
            return res.json({ success: false, error: 'Prompt not found' });
        }
        
        console.log(`Found prompt data for key: ${redisKey}`);
        
        try {
            // Handle double-quoted JSON strings
            let prompt;
            if (typeof promptJson === 'string') {
                if (promptJson.startsWith('"') && promptJson.endsWith('"')) {
                    // This is a double-quoted string, parse it as JSON
                    prompt = JSON.parse(promptJson);
                } else {
                    // This is already a JSON string
                    prompt = JSON.parse(promptJson);
                }
            } else {
                // This is already a parsed object
                prompt = promptJson;
            }
            
            // Ensure we have a valid prompt object
            if (!prompt || typeof prompt !== 'object') {
                console.error(`Invalid prompt data format for ${id}:`, promptJson);
                return res.json({ success: false, error: 'Invalid prompt data format' });
            }
            
            // Create a sanitized response
            const response = { 
                success: true, 
                prompt: {
                    id,
                    name: prompt.name || id,
                    description: prompt.description || '',
                    category: prompt.category || 'General',
                    template: prompt.template || ''
                }
            };
            
            console.log(`Successfully prepared prompt data for ID: ${id}`);
            res.json(response);
        } catch (error) {
            console.error(`Error parsing prompt ${id}:`, error);
            console.error('Raw prompt data:', promptJson);
            res.json({ success: false, error: `Error parsing prompt template: ${error.message}` });
        }
    } catch (error) {
        console.error('Error viewing prompt:', error);
        res.json({ success: false, error: error.message });
    }
});

// Update a specific prompt template
router.post('/update/:id', express.json(), async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, template, category } = req.body;
        
        if (!id) {
            return res.json({ success: false, error: 'Missing prompt ID' });
        }
        
        if (!template) {
            return res.json({ success: false, error: 'Template content is required' });
        }
        
        console.log(`Attempting to update prompt with ID: ${id}`);
        const client = initRedisClient();
        
        // Get the existing prompt from Redis to ensure it exists
        const redisKey = `llm:prompt:${id}`;
        console.log(`Looking up Redis key for update: ${redisKey}`);
        const promptJson = await client.get(redisKey);
        
        if (!promptJson) {
            console.log(`Prompt not found for update: ${redisKey}`);
            return res.json({ success: false, error: 'Prompt not found' });
        }
        
        // Parse the existing prompt
        let existingPrompt;
        try {
            if (typeof promptJson === 'string') {
                if (promptJson.startsWith('"') && promptJson.endsWith('"')) {
                    existingPrompt = JSON.parse(promptJson);
                } else {
                    existingPrompt = JSON.parse(promptJson);
                }
            } else {
                existingPrompt = promptJson;
            }
        } catch (parseError) {
            console.error(`Error parsing existing prompt JSON:`, parseError);
            return res.json({ success: false, error: 'Error parsing existing prompt data' });
        }
        
        // Create updated prompt object
        const updatedPrompt = {
            ...existingPrompt,
            name: name || existingPrompt.name,
            description: description || existingPrompt.description,
            template: template,
            category: category || existingPrompt.category,
            updated_at: new Date().toISOString()
        };
        
        // Save the updated prompt to Redis
        await client.set(redisKey, JSON.stringify(updatedPrompt));
        
        console.log(`Updated prompt: ${id}`);
        res.json({ 
            success: true, 
            prompt: {
                id,
                name: updatedPrompt.name || id,
                description: updatedPrompt.description || '',
                category: updatedPrompt.category || 'General',
                template: updatedPrompt.template || ''
            }
        });
    } catch (error) {
        console.error('Error updating prompt:', error);
        res.json({ success: false, error: error.message });
    }
});

module.exports = router;
