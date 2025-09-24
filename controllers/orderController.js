const Order = require('../models/Order');
const { generateOrderReference } = require('../utils/helpers');

// Create new order
exports.createOrder = async (req, res) => {
  try {
    const { items, deliveryInfo, paymentMethod } = req.body;
    
    // Calculate total
    const totalAmount = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);

    const order = new Order({
      user: req.userId, // From auth middleware
      items,
      deliveryInfo,
      paymentMethod,
      totalAmount,
      reference: generateOrderReference()
    });

    await order.save();

    // Different flows based on payment method
    if (paymentMethod === 'card') {
      // Initiate payment gateway process
      const paymentLink = await initiatePaymentGateway(order);
      return res.json({ 
        success: true, 
        paymentUrl: paymentLink,
        orderId: order._id 
      });
    }

    if (paymentMethod === 'transfer') {
      // Send bank details
      return res.json({
        success: true,
        orderId: order._id,
        bankDetails: getBankDetails(),
        amountToPay: order.totalAmount
      });
    }

    // For cash on delivery
    res.json({ 
      success: true, 
      orderId: order._id,
      message: "Order received. We'll contact you for delivery." 
    });

  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ success: false, message: 'Order processing failed' });
  }
};

// Get order status
exports.getOrderStatus = async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }
    res.json({ success: true, status: order.status });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Update order status
const updateOrderStatus = async (req, res) => {
  try {
    const { orderId } = req.params;
    const { status } = req.body;
    
    // Get the current order to check its status
    const currentOrder = await Order.findById(orderId);
    if (!currentOrder) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    // Only update if status is different
    if (currentOrder.status === status) {
      return res.json(currentOrder);
    }
    
    const updateData = { status };
    
    // Add timestamp to statusHistory when status changes
    const now = new Date();
    if (status === 'confirmed') {
      updateData['statusHistory.confirmed'] = now;
    } else if (status === 'preparing') {
      updateData['statusHistory.preparing'] = now;
    } else if (status === 'baking') {
      updateData['statusHistory.baking'] = now;
    } else if (status === 'out-for-delivery') {
      updateData['statusHistory.outForDelivery'] = now;
    } else if (status === 'delivered') {
      updateData['statusHistory.delivered'] = now;
    } else if (status === 'cancelled') {
      updateData['statusHistory.cancelled'] = now;
    }
    
    const order = await Order.findByIdAndUpdate(
      orderId,
      { $set: updateData },
      { new: true }
    );
    
    res.json(order);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Get user orders
const getUserOrders = async (req, res) => {
  try {
    const orders = await Order.find({ user: req.userId })
      .populate('items.product')
      .sort({ createdAt: -1 });
    
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// In orderController.js
exports.getUserOrders = async (req, res) => {
  const orders = await Order.find({ user: req.userId })
    .sort({ createdAt: -1 });
  res.json({ success: true, orders });
};

exports.cancelOrder = async (req, res) => {
  const order = await Order.findOneAndUpdate(
    { _id: req.params.id, user: req.userId },
    { status: 'cancelled' },
    { new: true }
  );
  res.json({ success: true, order });
};