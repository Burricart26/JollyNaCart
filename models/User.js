const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  fullName: { type: String, default: "" },
  name: { type: String, default: "" },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  address: { type: String, default: "" },
  passwordHash: String,
  passwordSalt: String,
  googleId: String,
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user"
  }
}, { timestamps: true });

module.exports = mongoose.model("User", UserSchema);