const mongoose = require("mongoose");
const orderSchema = new mongoose.Schema({
  // user order products
  orderId: {
    type: String,
    required: true,
    default: "ORDER-NO" + Date.now(),
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "user",
    required: true,
  },
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "products",
    required: true,
  },
  quantity: {
    type: Number,
    required: true,
  },
});
 
const Orders = mongoose.model("orders", orderSchema);
module.exports = Orders;