const mongoose = require("mongoose");

const OrderSchema = new mongoose.Schema({
  fullName: String,
  email: String,
  address: String,
  items: [String],
  total: Number,
  referenceImage: String
}, { timestamps: true });

module.exports = mongoose.model("Order", OrderSchema);
