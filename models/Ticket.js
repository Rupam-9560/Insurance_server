const mongoose = require("mongoose");

const ticketSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    subject: String,
    message: String,
    category: String,
    adminReply: String,
    status: {
      type: String,
      enum: ["open", "resolved"],
      default: "open"
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Ticket", ticketSchema);