const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    number: { type: String, required: true, unique: true },

    gender: {
      type: String,
      enum: ["male", "female", "other"],
      default: "male"
    },

    Date_of_Birth: { type: String },

    password: { type: String, required: true },

    role: { type: String, default: "user" },

    // ✅ OTP Fields (REQUIRED)
    resetOTP: { type: String },
    otpExpiry: { type: Date }
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);