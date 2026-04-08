import request from 'supertest';
import express from 'express';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import authRoutes from '../src/routes/auth.js';
import User from '../src/models/User.js';
import { connectDB, getDB } from '../src/db/database.js';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';

dotenv.config();

let mongoServer;
const app = express();
app.use(express.json());
app.use('/api/auth', authRoutes);

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongoServer.getUri();
  process.env.JWT_SECRET = 'test_secret';
  
  // Call connectDB so the 'isConnected()' in routes will return true
  await connectDB();

  // Seed user here to ensure we have credentials for test
  // wait, connectDB already calls seedUsers from User.js!
  // So 'admin' and 'viewer' will be seeded automatically.
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

describe('Auth Routes Test', () => {
  it('should return error if username or password is not provided', async () => {
    const res = await request(app).post('/api/auth/login').send({ username: 'admin' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Username and password required');
  });

  it('should login successfully with seeded admin credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'admin123' });
    
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.user.username).toBe('admin');
    expect(res.body.user.role).toBe('admin');
  });

  it('should fail to login with wrong credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'wrongpassword' });
    
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid credentials');
  });

  it('should register a new user using admin endpoint structure', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'newuser', password: 'password123', role: 'user' });

    expect(res.status).toBe(201);
    expect(res.body.message).toBe('User created');

    // verify it stored in DB
    const createdUser = await User.findOne({ username: 'newuser' });
    expect(createdUser).toBeTruthy();
    expect(createdUser.username).toBe('newuser');
  });
});
