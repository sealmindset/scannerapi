#!/usr/bin/env node
/**
 * Import Prompt Templates Script
 * 
 * This script imports prompt templates from a JSON file into Redis
 * for use with the Model Context Protocol (MCP) server.
 */

const fs = require('fs');
const path = require('path');
const promptManager = require('../utils/prompt-manager');

// Default paths
const DEFAULT_CONFIG_PATH = path.resolve(__dirname, '../../configs/llm_prompts.json');

/**
 * Import templates from a JSON file
 * @param {string} filePath - Path to the JSON file
 */
async function importTemplates(filePath) {
  try {
    console.log(`Importing templates from ${filePath}...`);
    
    // Read the JSON file
    const data = fs.readFileSync(filePath, 'utf8');
    const templates = JSON.parse(data);
    
    // Process the templates
    const processedTemplates = [];
    
    // Process main templates
    for (const [key, template] of Object.entries(templates)) {
      // Skip nested template objects
      if (typeof template !== 'object' || Array.isArray(template)) {
        continue;
      }
      
      // Skip section_templates and other nested template collections
      if (key === 'section_templates' || key.endsWith('_templates')) {
        continue;
      }
      
      // Add category and ID to the template
      const processedTemplate = {
        ...template,
        id: key,
        category: 'main'
      };
      
      processedTemplates.push(processedTemplate);
    }
    
    // Process section templates
    if (templates.section_templates) {
      for (const [sectionKey, sectionTemplate] of Object.entries(templates.section_templates)) {
        const processedTemplate = {
          ...sectionTemplate,
          id: `section_${sectionKey}`,
          category: 'section'
        };
        
        processedTemplates.push(processedTemplate);
      }
    }
    
    // Process any other template collections
    for (const [key, templateCollection] of Object.entries(templates)) {
      if (key !== 'section_templates' && key.endsWith('_templates') && typeof templateCollection === 'object') {
        for (const [templateKey, template] of Object.entries(templateCollection)) {
          const category = key.replace('_templates', '');
          const processedTemplate = {
            ...template,
            id: `${category}_${templateKey}`,
            category
          };
          
          processedTemplates.push(processedTemplate);
        }
      }
    }
    
    console.log(`Found ${processedTemplates.length} templates to import`);
    
    // Import the templates
    const importedIds = await promptManager.importTemplates(processedTemplates);
    
    console.log(`Successfully imported ${importedIds.length} templates`);
    console.log('Templates are now available through the MCP server');
    
    return importedIds;
  } catch (error) {
    console.error('Error importing templates:', error);
    process.exit(1);
  }
}

/**
 * Main function
 */
async function main() {
  // Parse command line arguments
  const args = process.argv.slice(2);
  const filePath = args[0] || DEFAULT_CONFIG_PATH;
  
  // Import templates
  await importTemplates(filePath);
  
  // Exit
  process.exit(0);
}

// Run the script
main();
