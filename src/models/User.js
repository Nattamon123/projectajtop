import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const { Schema } = mongoose;

const userSchema = new Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxlength: 32,
    },
    password: { type: String, required: true, select: false },
    role: { type: String, enum: ['admin', 'user'], default: 'user' },
    lastSeen: { type: Date, default: null },
    active: { type: Boolean, default: true },
  },
  { timestamps: true }
);

// Hash password before save
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Compare password
userSchema.methods.comparePassword = function (plain) {
  return bcrypt.compare(plain, this.password);
};

// Remove password from JSON output
userSchema.methods.toSafeObject = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

const User = mongoose.model('User', userSchema);

// Seed default admin + guest on first run
export async function seedUsers() {
  const count = await User.countDocuments();
  if (count > 0) return;

  await User.insertMany([
    { username: 'admin', password: await bcrypt.hash('admin123', 10), role: 'admin' },
    { username: 'viewer', password: await bcrypt.hash('viewer123', 10), role: 'user' },
  ]);
  console.log('🌱 Seeded default users: admin / admin123, viewer / viewer123');
}

export default User;
