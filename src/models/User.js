const mongoose = require("mongoose");

const connectionSchema = new mongoose.Schema({
  platform: { type: String, required: true, trim: true },
  siteName: { type: String, required: true, trim: true },
  siteUrl: { type: String, required: true, trim: true },
  installationId: { type: String, required: true },
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

// A plain `unique: true` on the subdocument field would index empty
// `connections` arrays as a null entry, so any two users with zero
// connections collide on insert. Scope uniqueness to documents that
// actually have an installationId.
userSchema.index(
  { "connections.installationId": 1 },
  { unique: true, partialFilterExpression: { "connections.installationId": { $exists: true } } }
);

module.exports = mongoose.model("User", userSchema);
