require('dotenv').config();
const fs = require('fs');
const express = require('express');
const router = express.Router();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const PDFDocument = require('pdfkit');
const authMiddleware = require('./middleware/Auth');
const User = require('./models/User');
const Order = require('./models/Order');
const Product = require('./models/Product');
const SupportRequest = require('./models/SupportRequest');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const path = require('path');
const app = express();
const authRoutes = require('./routes/auth');
const newsletterRoutes = require('./routes/newsletter');
const settingsRoutes = require('./routes/settings');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.REACT_APP_GOOGLE_CLIENT_ID);

// Middleware
const newsletterLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many subscription attempts from this IP, please try again later'
});
// Admin middleware
const adminOnly = (req, res, next) => {
  // You'll need to modify this based on how you store admin status
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ message: 'Admin access required' });
  }
};
app.use(cors({
  origin: ["http://localhost:3000", "https://noureesh-foods.netlify.app"],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE']
}));
// Track login activity
app.use((req, res, next) => {
  // Only track API requests, not static files
  if (req.path.startsWith('/api/') && !req.path.includes('/uploads')) {
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    
    // Store this for later use in login endpoints
    req.clientInfo = {
      ipAddress: ip,
      userAgent: userAgent,
      timestamp: new Date()
    };
  }
  next();
});
app.use(express.json());
app.use('/api/settings', settingsRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/newsletter/subscribe', newsletterLimiter, newsletterRoutes);
app.use('/api/newsletter', newsletterRoutes);

// Database connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

app.get("/", (req, res) => {
  res.send("Welcome to Noureesh Foods API 🚀");
});

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Helper to extract Cloudinary public_id from a Cloudinary URL
function getCloudinaryPublicIdFromUrl(url) {
  try {
    if (!url) return null;
    // Find the part after '/upload/' which contains the version (optional) and the public id + ext
    const uploadIndex = url.indexOf('/upload/');
    let publicPath = '';
    if (uploadIndex !== -1) {
      publicPath = url.substring(uploadIndex + '/upload/'.length);
      // Remove query string if present
      publicPath = publicPath.split('?')[0];
      // Remove file extension
      const dotIdx = publicPath.lastIndexOf('.');
      if (dotIdx !== -1) publicPath = publicPath.substring(0, dotIdx);
      return publicPath;
    }

    // Fallback: take last path segment without extension
    const parts = url.split('/');
    const last = parts[parts.length - 1].split('?')[0];
    const dot = last.lastIndexOf('.');
    return dot === -1 ? last : last.substring(0, dot);
  } catch (e) {
    console.error('Failed to extract Cloudinary public id from url', e);
    return null;
  }
}

// Create admin user if it doesn't exist
// const createAdminUser = async () => {
//   try {
//     const existingAdmin = await User.findOne({ email: 'admin@user.com' });
//     if (!existingAdmin) {
//       const hashedPassword = await bcrypt.hash('bakery@2025', 10);
//       const adminUser = new User({
//         name: 'Admin',
//         email: 'admin@user.com',
//         phone: '+2340000000000',
//         password: hashedPassword,
//         role: 'admin'
//       });
//       await adminUser.save();
//     } else {
//     }
//   } catch (error) {
//     console.error('Error creating admin user:', error);
//   }
// };

// createAdminUser();

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

// Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    // Validate input
    if (!name || !email || !phone || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      name,
      email,
      phone,
      // address: address || '',
      password: hashedPassword
    });

    await user.save();

    // Generate token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.status(201).json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        createdAt: user.createdAt
      },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ 
      message: 'No authorization header provided',
      solution: 'Make sure to include the Bearer token in Authorization header'
    });
  }

  const token = authHeader.split(' ')[1];
  if (!token || token === 'null' || token === 'undefined') {
    return res.status(401).json({ 
      message: 'Invalid or missing token',
      solution: 'Please login again to get a valid token'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Extract userId correctly based on your token structure
    req.userId = decoded.userId || decoded.id || decoded._id;
    req.user = { id: req.userId };
    req.userRole = decoded.role || 'customer';

    if (!req.userId) {
      return res.status(401).json({ 
        message: 'Invalid token format',
        solution: 'Token does not contain user information'
      });
    }

    next();
  } catch (err) {
    console.error('Token verification failed:', err);
    return res.status(401).json({ 
      message: 'Invalid token',
      solution: 'Please login again to get a new token'
    });
  }
};

app.post('/api/auth/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({ message: 'Email or phone and password are required' });
    }

    // Find user by email OR phone, include password field
    const user = await User.findOne({
      $or: [{ email: identifier }, { phone: identifier }]
    }).select('+password');

    if (!user) {
      await trackFailedLogin(identifier, req.clientInfo);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      await trackFailedLogin(user.email, req.clientInfo);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Track successful login
    await trackSuccessfulLogin(user._id, req.clientInfo);

    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });

    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        profileImage: user.profileImage || '',
        address: user.address || '',
        addresses: user.addresses || [],
        role: user.role || 'customer',
        createdAt: user.createdAt
      },
      token
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Helper function to track successful logins
async function trackSuccessfulLogin(userId, clientInfo) {
  try {
    await User.findByIdAndUpdate(userId, {
      $push: {
        loginActivity: {
          timestamp: clientInfo.timestamp,
          ipAddress: clientInfo.ipAddress,
          userAgent: clientInfo.userAgent,
          location: await getLocationFromIP(clientInfo.ipAddress),
          success: true
        }
      }
    });
  } catch (error) {
    console.error('Error tracking login:', error);
  }
}

// Helper function to track failed logins
async function trackFailedLogin(identifier, clientInfo) {
  try {
    let user;
    
    // Try to find user by email first
    user = await User.findOne({ email: identifier });
    
    // If not found by email, try by phone
    if (!user) {
      user = await User.findOne({ phone: identifier });
    }
    
    // If user is found, track the failed login with their ID
    if (user) {
      await User.findByIdAndUpdate(user._id, {
        $push: {
          loginActivity: {
            timestamp: clientInfo.timestamp,
            ipAddress: clientInfo.ipAddress,
            userAgent: clientInfo.userAgent,
            location: await getLocationFromIP(clientInfo.ipAddress),
            success: false
          }
        }
      });
    } else {
    }
  } catch (error) {
    console.error('Error tracking failed login:', error);
  }
}

async function getLocationFromIP(ip) {
  try {
    // Handle localhost and internal IPs for both IPv4 and IPv6
    const localIPs = [
      '127.0.0.1', '::1', '::ffff:127.0.0.1', '0:0:0:0:0:0:0:1',
      '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
      '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
      '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
      'fc00:', 'fd00:', 'fe80:' // IPv6 private ranges
    ];
    
    const isLocalIP = localIPs.some(localIP => ip.startsWith(localIP));
    if (isLocalIP) {
      return 'Local Network';
    }

    // Remove port if present (common with proxies) and handle IPv6 brackets
    let cleanIp = ip;
    if (ip.includes(':')) {
      // Handle IPv6 addresses with ports (e.g., [::1]:8080)
      if (ip.startsWith('[') && ip.includes(']:')) {
        cleanIp = ip.substring(1, ip.indexOf(']'));
      } else {
        cleanIp = ip.split(':')[0];
      }
    }

    // Use IP-API.com (free tier, no API key required)
    const response = await axios.get(`http://ip-api.com/json/${cleanIp}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query`, {
      timeout: 5000 // 5 second timeout
    });

    if (response.data.status === 'success') {
      const { city, regionName, country, isp } = response.data;
      const locationParts = [];
      
      if (city) locationParts.push(city);
      if (regionName && regionName !== city) locationParts.push(regionName);
      if (country) locationParts.push(country);
      
      let location = locationParts.join(', ');
      if (isp) location += ` (${isp})`;
      
      return location.trim();
    } else {
      console.warn('IP geolocation failed:', response.data.message);
      return 'Unknown Location';
    }
  } catch (error) {
    console.error('IP geolocation error:', error.message);
    
    // Fallback: Try ipinfo.io if ip-api fails
    try {
      const fallbackResponse = await axios.get(`https://ipinfo.io/${ip}/json?token=${process.env.IPINFO_TOKEN || ''}`, {
        timeout: 3000
      });
      
      if (fallbackResponse.data) {
        const { city, region, country, org } = fallbackResponse.data;
        const locationParts = [];
        
        if (city) locationParts.push(city);
        if (region && region !== city) locationParts.push(region);
        if (country) locationParts.push(country);
        
        let location = locationParts.join(', ');
        if (org) location += ` (${org})`;
        
        return location.trim();
      }
    } catch (fallbackError) {
      console.warn('Fallback IP geolocation also failed:', fallbackError.message);
    }
    
    return 'Location Unavailable';
  }
}

// Get login activity
app.get('/api/auth/login-activity', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('loginActivity');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Return the last 20 login activities, sorted by most recent
    const activities = user.loginActivity
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 20);

    res.json(activities);
  } catch (error) {
    console.error('Error fetching login activity:', error);
    res.status(500).json({ message: 'Server error fetching login activity' });
  }
});

app.post('/api/auth/verify-password', authenticate, async (req, res) => {
  try {
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password is required' 
      });
    }

    const user = await User.findById(req.userId).select('+password');
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    
    if (isMatch) {
      res.json({ 
        success: true, 
        message: 'Password verified successfully' 
      });
    } else {
      res.status(401).json({ 
        success: false, 
        message: 'Incorrect password' 
      });
    }
  } catch (error) {
    console.error('Password verification error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error during password verification' 
    });
  }
});

app.get('/api/auth/user-data', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId)
      .select('-password') // Exclude password
      .lean(); // Return plain JavaScript object
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json(user);
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ message: 'Server error while fetching user data' });
  }
});

// Google auth route
app.post('/api/auth/google', async (req, res) => {
  try {
    const accessToken = req.body.token;
    
    // Call Google's User Info API using the access token
    const googleRes = await axios.get(`https://www.googleapis.com/oauth2/v1/userinfo?access_token=${accessToken}`);
    const profile = googleRes.data;

    const { id, email, name, picture } = profile;

    // Find or create user in DB
    let user = await User.findOne({ email });
    let isNewUser = false;
    
    if (!user) {
      user = new User({
        name,
        email,
        profileImage: picture,
        googleId: id,
        isGoogleAuth: true
      });
      await user.save();
      isNewUser = true;
    }

    // Track successful login activity for Google auth users
    await trackSuccessfulLogin(user._id, {
      ipAddress: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      timestamp: new Date()
    });

    // Generate JWT token
    const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });

    // Check if profile needs completion
    const needsProfileCompletion = !user.phone;

    // Send back token and user
    res.json({
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        profileImage: user.profileImage,
        role: user.role,
        createdAt: user.createdAt
      },
      needsProfileCompletion,
      isNewUser
    });

  } catch (error) {
    console.error('Google login error:', error.response?.data || error.message);
    res.status(500).json({ message: 'Google login failed' });
  }
});

// Token verification endpoint
app.get('/api/auth/verify-token', authenticate, async (req, res) => {
  try {
    res.json({ valid: true, user: req.user });
  } catch (error) {
    res.status(401).json({ valid: false, message: 'Invalid token' });
  }
});

// Get all products
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get all users
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    console.error('Users fetch error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update user
app.put('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(user);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: "Error updating user" });
  }
});

// Delete user
app.delete('/api/users/:id', async (req, res) => {
  try {
    console.log('Deleting user:', req.params.id);
    await User.findByIdAndDelete(req.params.id);
    console.log('User deleted successfully');
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: "Error deleting user" });
  }
});

// Configure storage
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'noureesh-foods',
    allowed_formats: ['jpg', 'jpeg', 'png']
  },
});

// File filter for images only
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Only .jpg, .jpeg, or .png files are allowed'), false);
  }
};

// Multer upload middleware with size limit
const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
});

const calculateDeliveryFee = (address, settings) => {
  if (!address || !settings) return settings?.defaultDeliveryFee || 1500;
  
  const activeZones = settings.deliveryZones?.filter(zone => zone.isActive) || [];
  
  for (const zone of activeZones) {
    for (const area of zone.areas) {
      if (address.toLowerCase().includes(area.toLowerCase())) {
        return zone.deliveryFee;
      }
    }
  }
  
  return settings.defaultDeliveryFee || 1500;
};

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ message: 'Image file too large. Max size is 5MB.' });
  }
  next(err);
});

// Create new product
app.post('/api/products', upload.single('image'), async (req, res) => {
  try {
    const { name, category, price, stock, featured, rating } = req.body;
    const image = req.file ? req.file.path : '';
    
    // Validate required fields
    if (!name || !category || price === undefined || stock === undefined) {
      return res.status(400).json({ 
        success: false,
        message: 'Name, category, price and stock are required' 
      });
    }

    // Validate number fields
    if (isNaN(price) || isNaN(stock)) {
      return res.status(400).json({ 
        success: false,
        message: 'Price and stock must be numbers' 
      });
    }

    const product = new Product({
      name,
      category,
      price,
      stock,
      featured: featured === 'on' || featured === true,
      image,
      rating: rating ? parseFloat(rating) : 0,
      orders: 0, // Initial orders
      dateAdded: new Date()
    });

    await product.save();
    res.json(product);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Update product
app.put('/api/products/:id', upload.single('image'), async (req, res) => {
  try {
    const { name, category, price, stock, featured, rating } = req.body;
    const product = await Product.findById(req.params.id);
    
    if (!product) return res.status(404).json({ message: 'Product not found' });

    // Update fields
    product.name = name || product.name;
    product.category = category || product.category;
    product.price = price || product.price;
    product.stock = stock || product.stock;
    product.featured = featured === 'true' || featured === true;
    product.rating = rating ? parseFloat(rating) : product.rating;
    
    // Handle image update if new image is provided
    if (req.file) {
      // If previous image was uploaded to Cloudinary, remove it
      if (product.image && typeof product.image === 'string' && product.image.includes('res.cloudinary.com')) {
        try {
          const publicId = getCloudinaryPublicIdFromUrl(product.image);
          if (publicId) {
            await cloudinary.uploader.destroy(publicId);
          }
        } catch (e) {
          console.error('Error deleting old Cloudinary image:', e);
        }
      } else if (product.image) {
        // Fallback: local uploads
        const oldImagePath = path.join(__dirname, 'uploads', product.image);
        if (fs.existsSync(oldImagePath)) {
          try { fs.unlinkSync(oldImagePath); } catch (e) { console.error('Error deleting local image', e); }
        }
      }

      // Store the Cloudinary URL (multer-storage-cloudinary sets req.file.path to the URL)
      product.image = req.file.path || req.file.filename || '';
    }

    const updatedProduct = await product.save();
    res.json(updatedProduct);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Delete product
app.delete('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: 'Product not found' });

    // Delete associated image
    if (product.image) {
      try {
        if (typeof product.image === 'string' && product.image.includes('res.cloudinary.com')) {
          const publicId = getCloudinaryPublicIdFromUrl(product.image);
          if (publicId) {
            await cloudinary.uploader.destroy(publicId);
          }
        } else {
          const imagePath = path.join(__dirname, 'uploads', product.image);
          if (fs.existsSync(imagePath)) {
            fs.unlinkSync(imagePath);
          }
        }
      } catch (e) {
        console.error('Error deleting product image:', e);
      }
    }

    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: 'Product deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Create new order
app.post('/api/orders', authenticate, async (req, res) => {
  try {
    const { items, total, shippingAddress, phone, customerName, email, paymentMethod, deliveryNotes, scheduledDelivery } = req.body;

    // Validate required fields
    if (!items || !items.length || !total || !shippingAddress || !phone || !customerName || !email) {
      return res.status(400).json({ 
        success: false,
        message: 'Items, total, delivery address, phone, name, and email are required' 
      });
    }
    
    if (!req.userId) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required to create order'
      });
    }

    // Get settings to calculate delivery fee
    const Settings = require('./models/Settings');
    const settings = await Settings.findOne();
    
    // Calculate delivery fee based on address
    const calculatedDeliveryFee = calculateDeliveryFee(shippingAddress, settings);
    
    // Calculate subtotal
    const subtotal = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    
    // Calculate tax
    const taxRate = settings?.taxRate || 0;
    const taxAmount = (subtotal * (taxRate / 100));
    
    // Calculate total with proper delivery fee
    const finalTotal = subtotal + taxAmount + (subtotal >= (settings?.freeDeliveryThreshold || 10000) ? 0 : calculatedDeliveryFee);

    // Process items
    const orderItems = items.map(item => ({
      product: item.isCustomOrder ? null : item._id,
      name: item.name,
      price: item.price,
      quantity: item.quantity,
      image: item.image || '',
      isCustomOrder: item.isCustomOrder || false,
      customOrderData: item.isCustomOrder ? item.customOrderData : null
    }));

    // Create order with delivery fee information
    const order = new Order({
      customer: req.userId,
      items: orderItems,
      total: finalTotal,
      subtotal: subtotal,
      taxAmount: taxAmount,
      taxRate: taxRate,
      deliveryFee: subtotal >= (settings?.freeDeliveryThreshold || 10000) ? 0 : calculatedDeliveryFee,
      originalDeliveryFee: calculatedDeliveryFee, // Store the calculated fee before free delivery
      status: 'pending',
      shippingAddress,
      phone,
      customerName,
      email,
      paymentMethod: paymentMethod || 'cash_on_delivery',
      deliveryNotes: deliveryNotes || '',
      scheduledDelivery: scheduledDelivery || 'now',
      deliveryZone: await getDeliveryZone(shippingAddress, settings) // Store which zone was used
    });

    await order.save();

    // Populate order for response
    const populatedOrder = await Order.findById(order._id)
      .populate({
        path: 'items.product',
        match: { _id: { $ne: null } },
        select: 'name image'
      })
      .populate('customer', 'name email phone');

    res.status(201).json({
      success: true,
      order: populatedOrder,
      message: 'Order created successfully'
    });

  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error creating order' 
    });
  }
});

// Helper function to get delivery zone name
async function getDeliveryZone(address, settings) {
  if (!address || !settings) return 'Default Zone';
  
  const activeZones = settings.deliveryZones?.filter(zone => zone.isActive) || [];
  
  for (const zone of activeZones) {
    for (const area of zone.areas) {
      if (address.toLowerCase().includes(area.toLowerCase())) {
        return zone.name;
      }
    }
  }
  
  return 'Default Zone';
}

// Get all orders with customer information
app.get('/api/orders', async (req, res) => {
  try {
    const orders = await Order.find()
      .populate('customer', 'name email phone')
      .populate('items.product', 'name image')
      .sort({ createdAt: -1 });
    
    res.json(orders);
  } catch (error) {
    console.error('Orders fetch error:', error);
    res.status(500).json({ message: 'Server error fetching orders' });
  }
});

// Update order
app.put('/api/orders/:id', authenticate, async (req, res) => {
  try {
    const { status, paymentStatus } = req.body;
    const order = await Order.findById(req.params.id);
    
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    // Update status
    if (status) {
      order.status = status;
    }

    // Update paymentStatus
    if (paymentStatus) {
      order.paymentStatus = paymentStatus;
    }

    const updatedOrder = await order.save();
    
    // Populate for response
    const populatedOrder = await Order.findById(updatedOrder._id)
      .populate('customer', 'name email phone')
      .populate('items.product', 'name image');

    res.json(populatedOrder);
  } catch (error) {
    console.error('Order update error:', error);
    res.status(500).json({ message: 'Server error updating order' });
  }
});

// Delete order
app.delete('/api/orders/:id', authenticate, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    await Order.findByIdAndDelete(req.params.id);
    res.json({ message: 'Order deleted successfully' });
  } catch (error) {
    console.error('Order deletion error:', error);
    res.status(500).json({ message: 'Server error deleting order' });
  }
});

// Get current user profile
app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      address: user.address,
      profileImage: user.profileImage,
      addresses: user.addresses || [],
      createdAt: user.createdAt
    });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update user profile
app.put('/api/auth/update', authenticate, async (req, res) => {
  try {
    const { name, email, phone, address } = req.body;
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Update fields
    if (name) user.name = name;
    if (email) user.email = email;
    if (phone) user.phone = phone;
    if (address) user.address = address;
    
    await user.save();
    
    // Return updated user data (excluding password)
    const updatedUser = await User.findById(req.userId).select('-password');
    res.json(updatedUser);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add address
app.post('/api/auth/add-address', authenticate, async (req, res) => {
  try {
    const { label, address, phone } = req.body;
    
    if (!label || !address || !phone) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    // Validate Nigerian phone number
    const isValidNigerianPhone = /^0(70|80|81|90|91)[0-9]{8}$/.test(phone);
    if (!isValidNigerianPhone) {
      return res.status(400).json({ message: 'Invalid Nigerian phone number format' });
    }
    
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Create new address object
    const newAddress = {
      label,
      address,
      phone,
      isDefault: user.addresses.length === 0 // Set as default if it's the first address
    };
    
    // Add to addresses array
    user.addresses.push(newAddress);
    
    // If this is the first address, set it as the default address in the main profile too
    if (user.addresses.length === 1) {
      user.address = address;
    }
    
    await user.save();
    
    res.json({ 
      message: 'Address added successfully',
      addresses: user.addresses 
    });
  } catch (error) {
    console.error('Error adding address:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update address
app.put('/api/auth/update-address/:index', authenticate, async (req, res) => {
  try {
    const { index } = req.params;
    const { label, address, phone } = req.body;
    
    if (!label || !address || !phone) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    // Validate Nigerian phone number
    const isValidNigerianPhone = /^0(70|80|81|90|91)[0-9]{8}$/.test(phone);
    if (!isValidNigerianPhone) {
      return res.status(400).json({ message: 'Invalid Nigerian phone number format' });
    }
    
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Check if index is valid
    if (index < 0 || index >= user.addresses.length) {
      return res.status(400).json({ message: 'Invalid address index' });
    }
    
    // Update the address
    user.addresses[index] = {
      ...user.addresses[index],
      label,
      address,
      phone
    };
    
    await user.save();
    
    res.json({ 
      message: 'Address updated successfully',
      addresses: user.addresses 
    });
  } catch (error) {
    console.error('Error updating address:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Remove address
app.delete('/api/auth/remove-address/:index', authenticate, async (req, res) => {
  try {
    const { index } = req.params;
    
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Check if index is valid
    if (index < 0 || index >= user.addresses.length) {
      return res.status(400).json({ message: 'Invalid address index' });
    }
    
    // Check if we're removing the default address
    const isDefault = user.addresses[index].isDefault;
    
    // Remove the address
    user.addresses.splice(index, 1);
    
    // If we removed the default address and there are other addresses,
    // set the first one as the new default
    if (isDefault && user.addresses.length > 0) {
      user.addresses[0].isDefault = true;
      user.address = user.addresses[0].address;
    } else if (user.addresses.length === 0) {
      // If no addresses left, clear the main address field
      user.address = '';
    }
    
    await user.save();
    
    res.json({ 
      message: 'Address removed successfully',
      addresses: user.addresses 
    });
  } catch (error) {
    console.error('Error removing address:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Set default address
app.put('/api/auth/set-default-address', authenticate, async (req, res) => {
  try {
    const { addressIndex } = req.body;
    
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Check if index is valid
    if (addressIndex < 0 || addressIndex >= user.addresses.length) {
      return res.status(400).json({ message: 'Invalid address index' });
    }
    
    // Update all addresses to set isDefault to false
    user.addresses.forEach((addr, idx) => {
      addr.isDefault = idx === parseInt(addressIndex);
    });
    
    // Update the main address field
    user.address = user.addresses[addressIndex].address;
    
    await user.save();
    
    res.json({ 
      message: 'Default address updated successfully',
      address: user.address,
      addresses: user.addresses 
    });
  } catch (error) {
    console.error('Error setting default address:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Download My Data as PDF
app.get('/api/auth/download-data', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Create PDF
    const doc = new PDFDocument();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="my-data.pdf"');
    doc.pipe(res);

    // Header
    doc.fontSize(18).text('My Data Export', { align: 'center' });
    doc.moveDown();

    // Basic Info
    doc.fontSize(12).text(`Name: ${user.name}`);
    doc.text(`Email: ${user.email}`);
    doc.text(`Phone: ${user.phone || 'N/A'}`);
    doc.text(`Role: ${user.role}`);
    doc.text(`Created At: ${new Date(user.createdAt).toLocaleString()}`);
    doc.moveDown();

    // Addresses
    doc.fontSize(14).text('Saved Addresses:', { underline: true });
    if (user.addresses && user.addresses.length > 0) {
      user.addresses.forEach((addr, i) => {
        doc.text(
          `${i + 1}. ${addr.label || 'Address'} - ${addr.address}, Phone: ${addr.phone} ${addr.isDefault ? '(Default)' : ''}`
        );
      });
    } else {
      doc.text('No addresses saved.');
    }
    doc.moveDown();

    // Login Activity
    doc.fontSize(14).text('Login Activity:', { underline: true });
    if (user.loginActivity && user.loginActivity.length > 0) {
      user.loginActivity.forEach((log, i) => {
        doc.text(
          `${i + 1}. [${new Date(log.timestamp).toLocaleString()}] IP: ${log.ipAddress}, Location: ${log.location}, Success: ${log.success}`
        );
      });
    } else {
      doc.text('No login activity recorded.');
    }
    doc.moveDown();

    doc.end();
  } catch (err) {
    console.error('Error generating PDF:', err);
    res.status(500).json({ message: 'Failed to generate PDF' });
  }
});

// Delete Account
app.delete('/api/auth/delete-account', authMiddleware, async (req, res) => {
  try {
    // Check if user exists
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if user has any ongoing (non-delivered) orders
    const pendingOrders = await Order.find({
      customerId: req.user._id,
      status: { $nin: ["delivered", "cancelled"] }
    });

    if (pendingOrders.length > 0) {
      return res.status(400).json({
        message: "You cannot delete your account while you still have active orders. Please wait until all orders are delivered or cancelled."
      });
    }

    // Delete user account
    await User.findByIdAndDelete(req.user._id);
    await Order.deleteMany({ customerId: req.user._id });

    res.json({ message: "Account deleted successfully" });
  } catch (err) {
    console.error("Delete account error:", err);
    res.status(500).json({ message: "Server error while deleting account" });
  }
});

// Upload profile image
app.post('/api/auth/upload-profile-image', authenticate, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No image file provided' });
    }
    
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Delete old profile image if it exists
    if (user.profileImage) {
      try {
        if (typeof user.profileImage === 'string' && user.profileImage.includes('res.cloudinary.com')) {
          const publicId = getCloudinaryPublicIdFromUrl(user.profileImage);
          if (publicId) await cloudinary.uploader.destroy(publicId);
        } else {
          const oldImagePath = path.join(__dirname, 'uploads', user.profileImage);
          if (fs.existsSync(oldImagePath)) {
            fs.unlinkSync(oldImagePath);
          }
        }
      } catch (e) {
        console.error('Error deleting old profile image:', e);
      }
    }

    // Save new profile image URL (CloudinaryStorage sets req.file.path to the URL)
    user.profileImage = req.file.path || req.file.filename || '';
    await user.save();
    
    res.json({ 
      message: 'Profile image uploaded successfully',
      imageUrl: user.profileImage
    });
  } catch (error) {
    console.error('Error uploading profile image:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get orders for a specific user
app.get('/api/orders/my-orders', authenticate, async (req, res) => {
  try {
    const orders = await Order.find({ customer: req.userId })
      .populate('items.product', 'name image')
      .sort({ createdAt: -1 });
    
    res.json(orders);
  } catch (error) {
    console.error('Error fetching user orders:', error);
    res.status(500).json({ message: 'Server error fetching orders' });
  }
});

// Get featured products
app.get('/api/products/featured', async (req, res) => {
  try {
    const featuredProducts = await Product.find({ featured: true });
    res.json(featuredProducts);
  } catch (error) {
    console.error('Error fetching featured products:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get store settings
app.get('/api/settings', async (req, res) => {
  try {
    const Settings = require('./models/Settings');
    const settings = await Settings.findOne();
    
    if (!settings) {
      // Create default settings if none exist
      const defaultSettings = new Settings({
        taxRate: 0,
        freeDeliveryThreshold: 10000,
      });
      await defaultSettings.save();
      return res.json(defaultSettings);
    }
    
    res.json(settings);
  } catch (error) {
    console.error('Error fetching settings:', error);
    res.status(500).json({ message: 'Error fetching settings' });
  }
});

// Verify Paystack payment
app.post('/api/verify-payment', async (req, res) => {
  try {
    const { reference } = req.body;
    
    const response = await axios.get(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
      }
    });

    if (response.data.data.status === 'success') {
      res.json({ 
        success: true, 
        message: 'Payment verified successfully',
        paymentData: response.data.data
      });
    } else {
      res.status(400).json({ 
        success: false, 
        message: 'Payment verification failed' 
      });
    }
  } catch (error) {
    console.error('Payment verification error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Payment verification failed' 
    });
  }
});

app.get('/api/delivery-zones', async (req, res) => {
  try {
    const Settings = require('./models/Settings');
    const settings = await Settings.findOne();
    
    if (!settings) {
      return res.json({ deliveryZones: [] });
    }
    
    res.json({ 
      deliveryZones: settings.deliveryZones || [],
      defaultDeliveryFee: settings.defaultDeliveryFee || 1500
    });
  } catch (error) {
    console.error('Error fetching delivery zones:', error);
    res.status(500).json({ message: 'Error fetching delivery zones' });
  }
});

// Create a new support request
app.post('/api/support-requests', authenticate, async (req, res) => {
  try {
    const { subject, category, message, orderId, priority } = req.body;
    
    if (!subject || !message) {
      return res.status(400).json({ message: 'Subject and message are required' });
    }
    
    const supportRequest = new SupportRequest({
      customer: req.userId,
      subject,
      category: category || 'general',
      message,
      orderId: orderId || null,
      priority: priority || 'medium'
    });
    
    await supportRequest.save();
    
    // Populate customer details for response
    await supportRequest.populate('customer', 'name email');
    
    res.status(201).json({
      message: 'Support request submitted successfully',
      request: supportRequest
    });
  } catch (error) {
    console.error('Error creating support request:', error);
    res.status(500).json({ message: 'Server error creating support request' });
  }
});

// Get support requests for a customer
app.get('/api/support-requests/my-requests', authenticate, async (req, res) => {
  try {
    const requests = await SupportRequest.find({ customer: req.userId })
      .populate('customer', 'name email')
      .populate('orderId', '_id createdAt total')
      .sort({ createdAt: -1 });
    
    res.json(requests);
  } catch (error) {
    console.error('Error fetching support requests:', error);
    res.status(500).json({ message: 'Server error fetching support requests' });
  }
});

// Get all support requests (admin only)
app.get('/api/support-requests', authenticate, async (req, res) => {
  try {
    // Check if user is admin
    if (req.userRole !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }
    
    const { status, category, page = 1, limit = 10 } = req.query;
    
    let query = {};
    if (status) query.status = status;
    if (category) query.category = category;
    
    const requests = await SupportRequest.find(query)
      .populate('customer', 'name email phone')
      .populate('orderId', '_id createdAt total')
      .populate('assignedTo', 'name email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    const total = await SupportRequest.countDocuments(query);
    
    res.json({
      requests,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Error fetching support requests:', error);
    res.status(500).json({ message: 'Server error fetching support requests' });
  }
});

// Get a single support request
app.get('/api/support-requests/:id', authenticate, async (req, res) => {
  try {
    const request = await SupportRequest.findById(req.params.id)
      .populate('customer', 'name email phone')
      .populate('orderId')
      .populate('assignedTo', 'name email')
      .populate('responses.repliedBy', 'name email');
    
    if (!request) {
      return res.status(404).json({ message: 'Support request not found' });
    }
    
    // Check if user has access to this request
    const user = await User.findById(req.userId);
    if (user.role !== 'admin' && request.customer._id.toString() !== req.userId) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    res.json(request);
  } catch (error) {
    console.error('Error fetching support request:', error);
    res.status(500).json({ message: 'Server error fetching support request' });
  }
});

// Update a support request (admin only)
app.put('/api/support-requests/:id', authenticate, async (req, res) => {
  try {
    // Check if user is admin
    const user = await User.findById(req.userId);
    if (!user || user.role !== 'admin') {  // ← Fixed this line
      return res.status(403).json({ message: 'Admin access required' });
    }
    
    const { status, priority, assignedTo } = req.body;
    
    const request = await SupportRequest.findById(req.params.id);
    if (!request) {
      return res.status(404).json({ message: 'Support request not found' });
    }
    
    if (status) request.status = status;
    if (priority) request.priority = priority;
    if (assignedTo) request.assignedTo = assignedTo;
    
    await request.save();
    
    await request.populate('customer', 'name email phone');
    await request.populate('assignedTo', 'name email');
    
    res.json({
      message: 'Support request updated successfully',
      request
    });
  } catch (error) {
    console.error('Error updating support request:', error);
    res.status(500).json({ message: 'Server error updating support request' });
  }
});

// Add response to a support request
app.post('/api/support-requests/:id/response', authenticate, async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ message: 'Message is required' });
    }
    
    const request = await SupportRequest.findById(req.params.id);
    if (!request) {
      return res.status(404).json({ message: 'Support request not found' });
    }
    
    // Check if user has access to this request
    const user = await User.findById(req.userId);
    if (user.role !== 'admin' && request.customer.toString() !== req.userId) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    request.responses.push({
      message,
      repliedBy: req.userId
    });
    
    // If customer is replying, set status to in-progress
    if (user.role !== 'admin' && request.status === 'new') {
      request.status = 'in-progress';
    }
    
    await request.save();
    
    await request.populate('responses.repliedBy', 'name email');
    
    res.json({
      message: 'Response added successfully',
      request
    });
  } catch (error) {
    console.error('Error adding response to support request:', error);
    res.status(500).json({ message: 'Server error adding response' });
  }
});

// app.use('/uploads', express.static('uploads'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));