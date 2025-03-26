/**
 * Script to reset all LLM prompts in Redis and reload them from the JSON file
 * 
 * This script:
 * 1. Deletes all existing prompt keys from Redis
 * 2. Loads the prompts from the llm_prompts.json file
 */

const path = require('path');
const fs = require('fs');
const redis = require('../web-interface/utils/redis');
const redisClient = redis.client;

// Redis key prefix for prompts
const REDIS_PROMPT_PREFIX = 'llm:prompt:';
const REDIS_PROMPT_LIST_KEY = 'llm:prompts:list';

// Path to prompts file
const PROMPTS_FILE_PATH = path.join(__dirname, '..', 'configs', 'llm_prompts.json');

// Helper function to store prompt in Redis
async function storePromptInRedis(promptId, promptData) {
    try {
        console.log(`Storing prompt in Redis: ${promptId}`);
        const key = REDIS_PROMPT_PREFIX + promptId;
        await redisClient.set(key, JSON.stringify(promptData));
        
        // Add to list of prompts if not already there
        const exists = await redisClient.sIsMember(REDIS_PROMPT_LIST_KEY, promptId);
        
        if (!exists) {
            await redisClient.sAdd(REDIS_PROMPT_LIST_KEY, promptId);
            console.log(`Added prompt ${promptId} to list`);
        }
        
        return true;
    } catch (error) {
        console.error(`Error storing prompt in Redis: ${error.message}`);
        return false;
    }
}

// Function to clear all existing prompts from Redis
async function clearExistingPrompts() {
    try {
        console.log('Clearing existing prompts from Redis...');
        
        // Get all prompt keys
        const keys = await redisClient.keys(`${REDIS_PROMPT_PREFIX}*`);
        console.log(`Found ${keys.length} prompt keys to delete`);
        
        if (keys.length > 0) {
            // Delete all prompt keys
            const result = await redisClient.del(keys);
            console.log(`Deleted ${result} prompt keys`);
        }
        
        // Clear the prompts list
        await redisClient.del(REDIS_PROMPT_LIST_KEY);
        console.log('Cleared prompts list');
        
        return true;
    } catch (error) {
        console.error(`Error clearing prompts: ${error.message}`);
        return false;
    }
}

// Main function to load prompts from file to Redis
async function resetAndLoadPrompts() {
    try {
        console.log('Starting reset and load process...');
        
        // Clear existing prompts
        await clearExistingPrompts();
        
        console.log(`Loading prompts from file: ${PROMPTS_FILE_PATH}`);
        
        // Check if file exists
        if (!fs.existsSync(PROMPTS_FILE_PATH)) {
            console.error(`Prompts file not found: ${PROMPTS_FILE_PATH}`);
            return false;
        }
        
        // Read and parse prompts file
        const fileContents = fs.readFileSync(PROMPTS_FILE_PATH, 'utf8');
        console.log(`Successfully read prompts file with ${fileContents.length} characters`);
        const promptsData = JSON.parse(fileContents);
        console.log(`Parsed prompts file with ${Object.keys(promptsData).length} top-level keys`);
        
        // Store prompts in Redis
        for (const category in promptsData) {
            if (category === 'section_templates') {
                // Handle nested section templates
                for (const sectionId in promptsData[category]) {
                    const promptId = `${category}.${sectionId}`;
                    await storePromptInRedis(promptId, promptsData[category][sectionId]);
                    console.log(`Stored section template: ${promptId}`);
                }
            } else {
                await storePromptInRedis(category, promptsData[category]);
                console.log(`Stored prompt: ${category}`);
            }
        }
        
        console.log('Successfully reset and loaded all prompts to Redis');
        return true;
    } catch (error) {
        console.error(`Error resetting and loading prompts: ${error.message}`);
        return false;
    } finally {
        // Close Redis connection
        console.log('Closing Redis connection');
        await redisClient.quit();
    }
}

// Run the script
resetAndLoadPrompts()
    .then(success => {
        console.log(`Prompts reset and loading ${success ? 'completed successfully' : 'failed'}`);
        process.exit(success ? 0 : 1);
    })
    .catch(error => {
        console.error(`Unexpected error: ${error.message}`);
        process.exit(1);
    });
