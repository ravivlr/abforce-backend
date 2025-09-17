#!/usr/bin/env node

/**
 * Azure Cosmos DB Setup Script
 * 
 * This script helps set up Azure Cosmos DB connection and test the integration.
 * Run with: node scripts/setup-azure-cosmos.js
 */

const mongoose = require('mongoose');
require('dotenv').config();

// Azure Cosmos DB connection
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI not found in environment variables');
  console.log('\n🔧 Please create a .env file with:');
  console.log('MONGODB_URI=mongodb://your-cosmos-db-account:your-primary-key@your-cosmos-db-account.mongo.cosmos.azure.com:10255/?ssl=true&replicaSet=globaldb&retrywrites=false&maxIdleTimeMS=120000&appName=@your-cosmos-db-account@');
  process.exit(1);
}

console.log('🔗 Setting up Azure Cosmos DB connection...');
console.log('📍 MongoDB URI:', MONGODB_URI.replace(/\/\/.*@/, '//***:***@')); // Hide credentials

// Azure Cosmos DB specific options
const options = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
  retryWrites: false,
  maxIdleTimeMS: 120000,
  appName: '@abforce-auth-system@'
};

mongoose.connect(MONGODB_URI, options)
.then(() => {
  console.log('✅ Connected to Azure Cosmos DB successfully!');
  console.log('📊 Database:', mongoose.connection.name);
  console.log('🌐 Host:', mongoose.connection.host);
  console.log('🔌 Port:', mongoose.connection.port);
  console.log('🔒 SSL:', 'Enabled');
  
  // Test the connection
  return mongoose.connection.db.admin().ping();
})
.then(() => {
  console.log('🏓 Database ping successful!');
  console.log('🎉 Azure Cosmos DB setup complete!');
  console.log('\n📋 Next steps:');
  console.log('1. Start your backend server: npm start');
  console.log('2. Test the health endpoint: curl http://localhost:3000/health');
  console.log('3. Register a user and verify data persistence');
  console.log('4. Deploy to Azure App Service');
  
  process.exit(0);
})
.catch((error) => {
  console.error('❌ Azure Cosmos DB connection failed:', error.message);
  console.log('\n🔧 Troubleshooting:');
  console.log('1. Check your MONGODB_URI in .env file');
  console.log('2. Verify your Azure Cosmos DB account is active');
  console.log('3. Check network connectivity');
  console.log('4. Verify credentials and permissions');
  console.log('5. Ensure your IP is whitelisted (if firewall enabled)');
  
  process.exit(1);
});
