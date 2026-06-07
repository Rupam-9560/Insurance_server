const mongoose = require("mongoose");

const policySchema = new mongoose.Schema(
  {
    category: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Category",
      required: true,
    },
    subCategory: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "SubCategory",
      required: true,
    },

    name: String,

    sumAssured: Number,   // ⭐ MUST be this exact name
    premium: Number,
    tenure: Number,

    details: String,
  },
  { timestamps: true }
);

module.exports = mongoose.model("Policy", policySchema);
