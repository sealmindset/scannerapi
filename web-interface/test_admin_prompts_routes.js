
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
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Test server running on http://localhost:${PORT}`);
    console.log('Try accessing http://localhost:3000/admin/prompts');
});
