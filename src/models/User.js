const mongoose = require("mongoose");

const connectionSchema = new mongoose.Schema({
  platform: { type: String, required: true, trim: true },
  siteName: { type: String, required: true, trim: true },
  siteUrl: { type: String, required: true, trim: true },
  installationId: { type: String, required: true, unique: true },
  encryptedApiToken: { type: String, required: true },
  active: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
});

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  connections: [connectionSchema],
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("User", userSchema);
