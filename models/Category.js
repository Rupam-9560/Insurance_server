const mongoose = require("mongoose");

const categorySchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      unique: true,
    },
  },
  { timestamps: true } // ⭐ required for createdAt
);

module.exports = mongoose.model("Category", categorySchema);
