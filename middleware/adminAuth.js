const adminAuth = (req, res, next) => {
  try {
    // Check if user is admin
    if (!req.isAdmin) {
      return res.status(403).json({ message: 'Admin access required' });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = adminAuth;