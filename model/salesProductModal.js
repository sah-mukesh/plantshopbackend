// models/SaleProduct.js
const mongoose = require('mongoose');

const SaleProductSchema = new mongoose.Schema({
    saleProductName: { type: String, required: true },
    saleProductPrice: { type: Number, required: true },
    saleDiscount: { type: Number, required: true },
    saleRating: { type: Number, required: true },
    saleProductImage: {
        type: String,
        required: true,
        trim: true,
    }
});

module.exports = mongoose.model('SaleProduct', SaleProductSchema);
