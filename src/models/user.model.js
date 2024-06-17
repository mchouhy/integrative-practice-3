import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  first_name: {
    type: String,
    required: true,
  },
  last_name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  age: {
    type: Number,
    required: true,
  },
  role: {
    type: String,
    enum: ["usuario", "admin", "premium"],
    default: "usuario",
  },
  cart: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Cart",
  },
  resetToken: {
    token: String,
    expiresAt: Date,
  },
});

export const userModel = mongoose.model("user", userSchema);
