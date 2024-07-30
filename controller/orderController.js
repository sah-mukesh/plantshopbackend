const { json } = require("express");
const cloudinary = require("cloudinary");
const Orders = require("../model/orderModel");
 
// order created
const createOrder = async (req, res) => {
  console.log(req.body);
  const { userId, productId, quantity } = req.body;
  if (!userId || !productId || !quantity) {
    return res.json({
      success: false,
      message: "All fields are required",
    });
  }
  try {
    const newOrder = new Orders({
      userId: userId,
      productId: productId,
      quantity: quantity,
    });
    await newOrder.save();
    res.json({
      success: true,
      message: "Order Successfull",
      order: newOrder,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "server error",
    });
  }
};
 
 
const { ObjectId } = require("mongoose").Types;
 
const getOrders = async (req, res) => {
  const id = req.params.id.trim(); // Trim the value to remove whitespaces or newline characters
 
  console.log(id);
  try {
    const orders = await Orders.find({ userId: new ObjectId(id) }).populate(
      "productId"
    );
    console.log(id, orders);
    res.json({
      success: true,
      message: "Order fetched successfully",
      order: orders,
    });
  } catch (error) {
    res.send(error);
  }
};
// exporting
module.exports = {
  createOrder,
  getOrders,
};
 