const nodemailer = require('nodemailer');

const sendResetEmail = async (email, resetUrl) => {
	console.log(`Attempting to send email to: ${email}`);
	console.log(`Reset URL: ${resetUrl}`);
  // 1. Create transporter
  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
		port: 587,
		secure: false, // True for 465, false for other ports
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    },
		tls: {
			rejectUnauthorized: false // Bypass SSL certificate validation (temporary)
		},
		connectionTimeout: 10000, // 10 seconds timeout
  	greetingTimeout: 10000
  });

	transporter.verify(function(error, success) {
		if (error) {
			console.log('Email server connection error:', error);
		} else {
			console.log('Server is ready to send emails');
		}
	});

  // 2. Email options
  const mailOptions = {
    from: '"Noureesh Foods" <no-reply@noureeshfoods.com>',
    to: email,
    subject: 'Password Reset Request',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #e63946;">Noureesh Foods Password Reset</h2>
        <p>You requested to reset your password. Click the link below to proceed:</p>
        <a href="${resetUrl}" 
           style="display: inline-block; padding: 12px 24px; background-color: #e63946; 
                  color: white; text-decoration: none; border-radius: 4px; margin: 20px 0;">
          Reset Password
        </a>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="font-size: 12px; color: #777;">
          © ${new Date().getFullYear()} Noureesh Foods. All rights reserved.
        </p>
      </div>
    `
  };

  // 3. Send email
  await transporter.sendMail(mailOptions);
};

module.exports = sendResetEmail;