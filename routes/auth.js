const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const authMiddleware = require('../middleware/Auth');
const sendResetEmail = require('../utils/sendResetEmail');

router.get('/me', authMiddleware, (req, res) => {
  res.json(req.user); // user was set in the middleware
});

// Forgot Password - Generate Token and Send Email
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    // 1. Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // 2. Generate reset token (expires in 1 hour)
    const resetToken = jwt.sign(
      { id: user._id },
      process.env.JWT_RESET_SECRET,
      { expiresIn: '1h' }
    );

    // 3. Save token to user document
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
    await user.save();

    // 4. Send email
    const resetUrl = `${process.env.CLIENT_URL}/reset-password?token=${resetToken}&email=${email}`;
    await sendResetEmail(email, resetUrl);

    res.status(200).json({ message: 'Password reset email sent' });
  } catch (error) {
    res.status(500).json({ message: 'Error sending reset email' });
  }
});

// Reset Password - Verify Token and Update Password
router.post('/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;

    // 1. Find user
    const user = await User.findOne({ 
      email,
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    // 2. Verify token
    jwt.verify(token, process.env.JWT_RESET_SECRET);

    // 3. Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // 4. Update user
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    res.status(400).json({ message: 'Password reset failed', error: error.message });
  }
});

router.get('/user-data', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select('-password') // Exclude password
      .populate('addresses');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json(user);
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ message: 'Server error while fetching user data' });
  }
});

router.get('/my-requests', authMiddleware, async (req, res) => {
  try {
    const requests = await SupportRequest.find({ user: req.user.id })
      .populate('orderId')
      .sort({ createdAt: -1 });
    
    res.json(requests);
  } catch (error) {
    console.error('Error fetching support requests:', error);
    res.status(500).json({ message: 'Server error while fetching support requests' });
  }
});

module.exports = router;
