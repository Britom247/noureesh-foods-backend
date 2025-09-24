const express = require('express');
const router = express.Router();
const Settings = require('../models/Settings');

// Get settings
router.get('/', async (req, res) => {
  try {
    let settings = await Settings.findOne();
    if (!settings) {
      // Create default settings if none exist
      settings = new Settings();
      await settings.save();
    }
    res.json(settings);
  } catch (error) {
    console.error('Error fetching settings:', error);
    res.status(500).json({ message: 'Failed to fetch settings' });
  }
});

// Update settings
router.put('/', async (req, res) => {
  try {
    const { store, notifications, security, payments } = req.body;
    
    let settings = await Settings.findOne();
    if (!settings) {
      settings = new Settings();
    }

    // Update delivery zones if provided
    if (req.body.deliveryZones) {
      settings.store.deliveryZones = req.body.deliveryZones;
    }

    // Update only the provided sections
    if (store) settings.store = { ...settings.store, ...store };
    if (notifications) settings.notifications = { ...settings.notifications, ...notifications };
    if (security) settings.security = { ...settings.security, ...security };
    if (payments) settings.payments = { ...settings.payments, ...payments };

    await settings.save();
    res.json(settings);
  } catch (error) {
    console.error('Error updating settings:', error);
    res.status(500).json({ message: 'Failed to update settings' });
  }
});

module.exports = router;