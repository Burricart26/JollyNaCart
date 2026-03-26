const mongoose = require("mongoose");

const ChatMessageSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  sender: {
    type: String,
    enum: ["user", "admin", "system", "auto"],
    required: true
  },
  text: {
    type: String,
    required: true
  }
}, { timestamps: true });

module.exports = mongoose.model("ChatMessage", ChatMessageSchema);
