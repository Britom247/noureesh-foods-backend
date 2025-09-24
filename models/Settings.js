// models/Settings.js
const mongoose = require('mongoose');

const deliveryZoneSchema = new mongoose.Schema({
  _id: { type: String },
  name: { type: String, required: true },
  areas: [{ type: String, required: true }],
  deliveryFee: { type: Number, required: true },
  minOrderAmount: { type: Number, default: 0 },
  estimatedDeliveryTime: { type: String, default: '30-45 minutes' },
  isActive: { type: Boolean, default: true }
}, { _id: true });

const settingsSchema = new mongoose.Schema({
  store: {
    storeName: { type: String, default: 'Noureesh Foods' },
    storeEmail: { type: String, default: 'contact@noureeshfoods.com' },
    storePhone: { type: String, default: '+234 123 456 7890' },
    storeAddress: { type: String, default: '123 Food Street, Lagos, Nigeria' },
    currency: { type: String, default: 'NGN' },
    taxRate: { type: Number, default: 0 },
    defaultDeliveryFee: { type: Number, default: 1500 },
    freeDeliveryThreshold: { type: Number, default: 10000 },
    deliveryZones: [deliveryZoneSchema],
    openingTime: { type: String, default: '08:00' },
    closingTime: { type: String, default: '22:00' }
  },
  notifications: {
    emailNotifications: { type: Boolean, default: true },
    orderAlerts: { type: Boolean, default: true },
    lowStockAlerts: { type: Boolean, default: true },
    newUserAlerts: { type: Boolean, default: false },
    marketingEmails: { type: Boolean, default: false }
  },
  security: {
    twoFactorAuth: { type: Boolean, default: false },
    sessionTimeout: { type: Number, default: 60 },
    passwordExpiry: { type: Number, default: 90 },
    loginAttempts: { type: Number, default: 5 },
    ipWhitelist: [{ type: String }]
  },
  payments: {
    cashOnDelivery: { type: Boolean, default: true },
    bankTransfer: { type: Boolean, default: true },
    cardPayment: { type: Boolean, default: false },
    paystack: { type: Boolean, default: false },
    flutterwave: { type: Boolean, default: false }
  }
}, {
  timestamps: true
});

// Ensure only one settings document exists
settingsSchema.statics.getSettings = function() {
  return this.findOne().then(settings => {
    if (!settings) {
      return this.create({});
    }
    return settings;
  });
};

module.exports = mongoose.model('Settings', settingsSchema);