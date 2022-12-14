const mongoose = require("mongoose");
const ProductSchema = new mongoose.Schema(
  {
    category: {
      type: String,
      default: "",
      required: true,
    },
    direction: {
      type: String,
      default: "DESC",
    },
    name: {
      type: String,
      default: "",
      required: true,
    },
    sortBy: {
      type: String,
      default: "productId",
    },
  },
  { timestamps: true }
);
module.exports = mongoose.model("products", ProductSchema);