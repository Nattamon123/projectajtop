import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { seedUsers } from '../models/User.js';

// Load environment variables
dotenv.config();

/**
 * Standalone seed script to populate the database.
 * Run using: npm run seed
 */
async function runSeed() {
  const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017/netwatch';
  
  try {
    console.log(`⏳ Connecting to MongoDB at ${uri}...`);
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 5000,
    });
    console.log(`✅ MongoDB connected successfully.`);

    // Run user seeding
    await seedUsers();
    
    // Add additional logic here for seeding future collections (e.g., mock packets)

    console.log('✅ All seeds completed successfully!');
    process.exit(0);
  } catch (err) {
    console.error('❌ Seeding failed:', err.message);
    process.exit(1);
  } finally {
    // Attempt graceful disconnect
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect();
      console.log('🔌 Disconnected from DB');
    }
  }
}

runSeed();
