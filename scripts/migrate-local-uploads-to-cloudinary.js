require('dotenv').config();
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;

// Configure Cloudinary from env
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/noureesh-foods';

async function main() {
  if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
    console.error('Please set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET in your environment before running this script.');
    process.exit(1);
  }

  console.log('Connecting to MongoDB...');
  await mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log('Connected to MongoDB');

  const Product = require('../models/Product');
  const User = require('../models/User');

  const uploadsDir = path.join(__dirname, '..', 'uploads');

  const dryRun = process.argv.includes('--dry-run');
  console.log(dryRun ? 'Running in DRY-RUN mode. No DB changes or deletions will be made.' : 'Running in LIVE mode. DB will be updated and local files may be deleted.');

  try {
    // Migrate product images
    const products = await Product.find();
    console.log(`Found ${products.length} products`);

    for (const p of products) {
      const img = p.image;
      if (!img) continue;
      // Skip if already a URL
      if (typeof img === 'string' && (img.startsWith('http://') || img.startsWith('https://') || img.includes('res.cloudinary.com'))) {
        console.log(`Skipping product ${p._id} (already has remote URL)`);
        continue;
      }

      const localPath = path.join(uploadsDir, img);
      if (!fs.existsSync(localPath)) {
        console.warn(`Local file for product ${p._id} not found: ${localPath}`);
        continue;
      }

      console.log(`Uploading product ${p._id} image ${img} to Cloudinary...`);
      const publicId = `noureesh-foods/products/${path.parse(img).name}`;
      if (!dryRun) {
        const res = await cloudinary.uploader.upload(localPath, { public_id: publicId, folder: 'noureesh-foods/products' });
        p.image = res.secure_url;
        await p.save();
        console.log(`Updated product ${p._id} with Cloudinary URL`);

        // Delete local file
        try { fs.unlinkSync(localPath); console.log(`Deleted local file ${localPath}`); } catch (e) { console.warn('Failed to delete local file', e); }
      }
    }

    // Migrate user profile images
    const users = await User.find();
    console.log(`Found ${users.length} users`);
    for (const u of users) {
      const img = u.profileImage;
      if (!img) continue;
      if (typeof img === 'string' && (img.startsWith('http://') || img.startsWith('https://') || img.includes('res.cloudinary.com'))) {
        console.log(`Skipping user ${u._id} (already has remote URL)`);
        continue;
      }

      const localPath = path.join(uploadsDir, img);
      if (!fs.existsSync(localPath)) {
        console.warn(`Local file for user ${u._id} not found: ${localPath}`);
        continue;
      }

      console.log(`Uploading user ${u._id} profile image ${img} to Cloudinary...`);
      const publicId = `noureesh-foods/profiles/${path.parse(img).name}`;
      if (!dryRun) {
        const res = await cloudinary.uploader.upload(localPath, { public_id: publicId, folder: 'noureesh-foods/profiles' });
        u.profileImage = res.secure_url;
        await u.save();
        console.log(`Updated user ${u._id} with Cloudinary URL`);

        // Delete local file
        try { fs.unlinkSync(localPath); console.log(`Deleted local file ${localPath}`); } catch (e) { console.warn('Failed to delete local file', e); }
      }
    }

    console.log('Migration complete');
  } catch (err) {
    console.error('Migration error', err);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
}

main();
