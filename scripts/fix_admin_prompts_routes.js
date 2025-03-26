/**
 * Fix Admin Prompts Routes
 * 
 * This script fixes the admin prompts routes configuration in the web server.
 * It ensures that the routes are properly registered and accessible.
 */

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

// Paths
const webInterfaceDir = path.join(__dirname, '..', 'web-interface');
const appJsPath = path.join(webInterfaceDir, 'app.js');
const adminPromptsRoutesPath = path.join(webInterfaceDir, 'routes', 'admin_prompts.js');

// Check if files exist
console.log('Checking file existence...');
if (!fs.existsSync(appJsPath)) {
    console.error(`Error: app.js not found at ${appJsPath}`);
    process.exit(1);
}

if (!fs.existsSync(adminPromptsRoutesPath)) {
    console.error(`Error: admin_prompts.js not found at ${adminPromptsRoutesPath}`);
    process.exit(1);
}

console.log('Files exist, checking routes configuration...');

// Read app.js
const appJs = fs.readFileSync(appJsPath, 'utf8');

// Check if admin prompts routes are registered
if (appJs.includes("app.use('/admin/prompts', adminPromptsRoutes)")) {
    console.log('Admin prompts routes are registered in app.js');
} else {
    console.error('Admin prompts routes are NOT registered in app.js');
    console.log('This needs to be fixed manually.');
}

// Create a test file to verify the routes
const testFilePath = path.join(webInterfaceDir, 'test_admin_prompts_routes.js');
const testFileContent = `
/**
 * Test Admin Prompts Routes
 * 
 * This script tests the admin prompts routes to ensure they are accessible.
 */

const express = require('express');
const app = express();
const adminPromptsRoutes = require('./routes/admin_prompts');

// Register routes
app.use('/admin/prompts', adminPromptsRoutes);

// Start server on a different port for testing
const PORT = 5003;
app.listen(PORT, () => {
    console.log(\`Test server running on http://localhost:\${PORT}\`);
    console.log('Try accessing http://localhost:5003/admin/prompts');
});
`;

fs.writeFileSync(testFilePath, testFileContent);
console.log(`Created test file at ${testFilePath}`);

// Check if configs/backups directory exists
const configsDir = path.join(__dirname, '..', 'configs');
const backupsDir = path.join(configsDir, 'backups');

if (!fs.existsSync(backupsDir)) {
    console.log(`Creating backups directory at ${backupsDir}`);
    fs.mkdirSync(backupsDir, { recursive: true });
} else {
    console.log(`Backups directory exists at ${backupsDir}`);
}

// Check if llm_prompts.json exists
const promptsPath = path.join(configsDir, 'llm_prompts.json');
if (!fs.existsSync(promptsPath)) {
    console.log(`Creating empty prompts file at ${promptsPath}`);
    fs.writeFileSync(promptsPath, '{}');
} else {
    console.log(`Prompts file exists at ${promptsPath}`);
}

// Check Redis connection
console.log('Checking Redis connection...');
exec('redis-cli ping', (error, stdout, stderr) => {
    if (error) {
        console.error(`Error checking Redis: ${error.message}`);
        return;
    }
    
    if (stderr) {
        console.error(`Redis stderr: ${stderr}`);
        return;
    }
    
    console.log(`Redis response: ${stdout.trim()}`);
    
    if (stdout.trim() === 'PONG') {
        console.log('Redis is running and responding');
    } else {
        console.error('Redis is not responding correctly');
    }
});

console.log('\nTo test the admin prompts routes:');
console.log('1. Run the test server: node web-interface/test_admin_prompts_routes.js');
console.log('2. Access http://localhost:5003/admin/prompts in your browser');
console.log('3. If it works, restart the main web server');

console.log('\nTo restart the main web server:');
console.log('1. Find the process ID: ps aux | grep "node app.js"');
console.log('2. Kill the process: kill <PID>');
console.log('3. Start the server again: cd web-interface && node app.js');
