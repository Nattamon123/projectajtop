import mongoose from 'mongoose';

const { Schema } = mongoose;

const packetSchema = new Schema(
  {
    timestamp: { type: Date, required: true, default: Date.now },
    srcIp: { type: String, index: true },
    dstIp: { type: String },
    srcPort: { type: Number },
    dstPort: { type: Number },
    protocol: { type: String, index: true },        // TCP | UDP | ICMP
    appProtocol: { type: String, index: true },     // HTTP | HTTPS | DNS | SSH …
    size: { type: Number },                         // bytes
    encrypted: { type: Boolean, index: true },
    tlsVersion: { type: String, default: null },    // TLS 1.2 | TLS 1.3 | SSL 3.0 | SSH-2.0
    interface: { type: String },
  },
  {
    // Disable versionKey (__v) and id for lean performance
    versionKey: false,
  }
);

// TTL: auto-delete packets older than 24 hours
packetSchema.index({ timestamp: 1 }, { expireAfterSeconds: 86400 });

// Compound indexes for common query patterns
packetSchema.index({ protocol: 1, timestamp: -1 });
packetSchema.index({ encrypted: 1, timestamp: -1 });
packetSchema.index({ appProtocol: 1, timestamp: -1 });

const Packet = mongoose.model('Packet', packetSchema);

export default Packet;
