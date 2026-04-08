import mongoose from 'mongoose';

let _connected = false;

export async function connectDB() {
  const uri = process.env.MONGODB_URI;

  try {
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 5000,
    });
    _connected = true;
    console.log(`✅ MongoDB connected → ${uri}`);

    // Seed default users on first run
    const { seedUsers } = await import('../models/User.js');
    await seedUsers();
  } catch (err) {
    console.error('❌ MongoDB connection failed:', err.message);
    console.warn('⚠️  Running WITHOUT persistent storage.');
    console.warn('   To enable: start MongoDB and set MONGODB_URI in .env');
  }
}

/** Returns true if MongoDB is connected */
export function isConnected() {
  return _connected;
}

export function getDB() {
  return mongoose.connection;
}

export async function disconnectDB() {
  if (_connected) {
    await mongoose.disconnect();
    _connected = false;
    console.log('🔌 MongoDB connection closed gracefully.');
  }
}
