const express = require('express');
const router = express.Router();
// const validator = require('validator');
// const Newsletter = require('../models/Newsletter');
const Subscriber = require('../models/Subscriber');

// Subscribe to newsletter
router.post('/subscribe', async (req, res) => {
  try {
    const { email } = req.body;
    
    // Validate email
    if (!email || !email.includes('@')) {
      return res.status(400).json({ 
        success: false,
        message: 'Please provide a valid email address' 
      });
    }

    // if (!validator.isEmail(email)) {
    //   return res.status(400).json({ 
    //     success: false, 
    //     message: 'Please provide a valid email address' 
    //   });
    // }

    // Check if already subscribed
    const exists = await Subscriber.findOne({ email });
    if (exists) {
      return res.status(200).json({ 
        success: true, 
        message: 'This email is already subscribed',
        alreadySubscribed: true
      });
    }

    const subscriber = new Subscriber({ email });
    await subscriber.save();

    res.status(201).json({ 
      success: true, 
      message: 'Thank you for subscribing!',
      data: subscriber
    });
  } catch (err) {
    console.error('Subscription error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during subscription' 
    });
  }
});

router.post('/unsubscribe', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    const result = await Newsletter.findOneAndUpdate(
      { email },
      { isActive: false },
      { new: true }
    );

    if (!result) {
      return res.status(404).json({ 
        success: false, 
        message: 'Email not found in our subscriptions' 
      });
    }

    res.status(200).json({ 
      success: true, 
      message: 'You have been unsubscribed',
      data: result
    });
  } catch (err) {
    console.error('Unsubscription error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Unsubscription failed. Please try again.' 
    });
  }
});

module.exports = router;