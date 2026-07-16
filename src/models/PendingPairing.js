const mongoose = require("mongoose");

const pendingPairingSchema = new mongoose.Schema({
  installationId: { type: String, required: true, unique: true },
  pairingSecretHash: { type: String, required: true },
  platform: { type: String, required: true },
  siteName: { type: String, required: true },
  siteUrl: { type: String, required: true },
  status: { type: String, enum: ["pending", "linked"], default: "pending" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  connectionId: { type: mongoose.Schema.Types.ObjectId },
  encryptedApiToken: { type: String },
  createdAt: { type: Date, default: Date.now, expires: 600 },
});

module.exports = mongoose.model("PendingPairing", pendingPairingSchema);
