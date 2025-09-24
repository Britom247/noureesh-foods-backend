const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
  phone: { type: String },
  role: {
    type: String,
    enum: ['customer', 'admin'],
    default: 'customer'
  },
  address: { type: String },
  addresses: [{
    label: { type: String },
    address: { type: String },
    phone: { type: String },
    isDefault: { type: Boolean, default: false }
  }],
  password: { type: String, minlength: 8, select: false },
  profileImage: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  resetToken: {type: String},
  resetTokenExpiry: {type: Date},
  isGoogleAuth: {
    type: Boolean,
    default: false
  },
  loginActivity: [{
    timestamp: { type: Date, default: Date.now },
    ipAddress: String,
    userAgent: String,
    location: String,
    success: { type: Boolean, default: true }
  }]
}, {
  timestamps: true
});

module.exports = mongoose.model('User', userSchema);