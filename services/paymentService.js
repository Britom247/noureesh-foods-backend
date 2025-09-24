const axios = require('axios');
const Order = require('../models/Order');

// Initialize Paystack payment
exports.initiatePaystackPayment = async (order) => {
  const payload = {
    email: order.deliveryInfo.email,
    amount: order.totalAmount * 100, // in kobo
    reference: order.reference,
    callback_url: `${process.env.FRONTEND_URL}/order/verify/${order._id}`,
    metadata: {
      orderId: order._id.toString(),
      custom_fields: [
        {
          display_name: "Customer Name",
          variable_name: "customer_name",
          value: order.deliveryInfo.name
        }
      ]
    }
  };

  const response = await axios.post(
    'https://api.paystack.co/transaction/initialize',
    payload,
    {
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json'
      }
    }
  );

  return response.data.data.authorization_url;
};

// Verify payment
exports.verifyPayment = async (reference) => {
  const response = await axios.get(
    `https://api.paystack.co/transaction/verify/${reference}`,
    {
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
      }
    }
  );

  if (response.data.data.status === 'success') {
    const order = await Order.findOne({ reference });
    if (order && !order.paymentVerified) {
      order.paymentVerified = true;
      order.status = 'paid';
      await order.save();
      
      // Send confirmation email
      await sendOrderConfirmation(order);
      
      return { success: true, order };
    }
  }
  
  return { success: false };
};