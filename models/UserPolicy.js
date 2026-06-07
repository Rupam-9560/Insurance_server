const mongoose = require("mongoose");

const userPolicySchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    policy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Policy",
      required: true,
    },

    status: {
      type: String,
      enum: ["pending", "approved", "disapproved"],
      default: "pending",
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("UserPolicy", userPolicySchema);
