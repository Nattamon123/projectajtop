import mongoose from 'mongoose';

const alertSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    default: Date.now,
  },
  severity: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    required: true,
  },
  type: {
    type: String,
    required: true,
  },
  message: {
    type: String,
    required: true,
  },
  metadata: {
    srcIp: String,
    dstIp: String,
    protocol: String,
    details: mongoose.Schema.Types.Mixed,
  },
});

const Alert = mongoose.model('Alert', alertSchema);

export default Alert;
